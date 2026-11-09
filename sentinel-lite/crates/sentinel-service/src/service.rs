//! Windows Service Control Manager integration.

use crate::app;
use crate::engine::AppPaths;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "SentinelLite";
const DISPLAY_NAME: &str = "Vigil Endpoint Protection";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Entry point when launched by the SCM.
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("not started by the Service Control Manager")
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %format!("{e:#}"), "service failed");
    }
}

fn status(state: ServiceState, controls: ServiceControlAccept, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    let paths = AppPaths::new(sentinel_protocol::paths::data_dir());
    app::init_logging(&paths, false);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let mut tx = Some(tx);
    let handle = service_control_handler::register(SERVICE_NAME, move |ctrl| match ctrl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = tx.take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2) // the engine's heavy lifting is on dedicated threads
        .enable_all()
        .build()?;
    let result = rt.block_on(app::run(paths, async {
        let _ = rx.await;
    }));

    let code = if result.is_ok() { 0 } else { 1 };
    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), code))?;
    result
}

fn service_info() -> Result<ServiceInfo> {
    Ok(ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem: required for ETW kernel providers and all-profile scans
        account_password: None,
    })
}

fn wait_for(service: &windows_service::service::Service, state: ServiceState) -> Result<()> {
    for _ in 0..60 {
        if service.query_status()?.current_state == state {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    anyhow::bail!("timed out waiting for service to reach {state:?}")
}

/// Idempotent: installs, or (on upgrade) stops, reconfigures and restarts.
pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = service_info()?;
    let access =
        ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            if existing.query_status()?.current_state != ServiceState::Stopped {
                let _ = existing.stop();
                wait_for(&existing, ServiceState::Stopped)?;
            }
            existing.change_config(&info)?;
            existing
        }
        Err(_) => manager.create_service(&info, access)?,
    };
    service.set_description("Real-time malware protection engine for Vigil.")?;
    // Restart automatically if the engine ever crashes.
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(120),
            },
        ]),
    })?;
    // Also apply the failure actions when the process exits with an error, not only on crashes.
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.start::<&str>(&[])?;
    wait_for(&service, ServiceState::Running)?;
    println!("{SERVICE_NAME} installed and running.");
    Ok(())
}

pub fn start() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
    service.start::<&str>(&[])?;
    wait_for(&service, ServiceState::Running)
}

pub fn stop() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        wait_for(&service, ServiceState::Stopped)?;
    }
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(500));
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
        }
        // A service that does not stop would stay registered ("marked for deletion")
        // until its process exits. Never let a hang block uninstalling: end it.
        let st = service.query_status()?;
        if st.current_state != ServiceState::Stopped {
            if let Some(pid) = st.process_id {
                eprintln!("{SERVICE_NAME} did not stop within 10 s; ending process {pid}");
                crate::platform::terminate(pid);
                for _ in 0..20 {
                    std::thread::sleep(Duration::from_millis(250));
                    if service.query_status()?.current_state == ServiceState::Stopped {
                        break;
                    }
                }
            }
        }
    }
    service.delete()?;
    println!("Removed {SERVICE_NAME}.");
    Ok(())
}
