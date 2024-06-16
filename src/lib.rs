extern crate kubewarden_policy_sdk as kubewarden;

use guest::prelude::*;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};
use kubewarden_policy_sdk::wapc_guest as guest;
use lazy_static::lazy_static;
use slog::{info, o, warn, Logger};

use settings::Settings;

mod settings;

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => settings::POLICY_NAME)
    );
}

const PORT_FORWARD: &str = "port-forward";
const PORT_FORWARD_KIND: &str = "PodPortForwardOptions";

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");
    if validation_request.request.kind.kind != PORT_FORWARD_KIND {
        warn!(LOG_DRAIN, "policy validates '{}' only, accepting resource", PORT_FORWARD_KIND; "kind" => &validation_request.request.kind.kind);
        return kubewarden::accept_request();
    }

    if validation_request.request.dry_run {
        info!(LOG_DRAIN, "dry run mode, accepting resource");
        return kubewarden::accept_request();
    }

    // service account username
    let username = &validation_request.request.user_info.username;
    // pod name
    let pod_name = &validation_request.request.name;
    // namespace
    let namespace = &validation_request.request.namespace;

    info!(LOG_DRAIN,  "connecting pod"; "name" => pod_name, "namespace" => namespace);
    if !validation_request
        .settings
        .exempt(username, pod_name, namespace)
    {
        warn!(LOG_DRAIN, "reject resource '{}'", PORT_FORWARD_KIND);
        return kubewarden::reject_request(
            Some(format!(
                "The '{}' is on the deny kubectl sub-command list",
                PORT_FORWARD
            )),
            None,
            None,
            None,
        );
    }
    warn!(LOG_DRAIN, "accepting resource with exemption");
    kubewarden::accept_request()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use kubewarden_policy_sdk::test::Testcase;

    use super::*;

    #[test]
    fn reject_connect() -> Result<(), ()> {
        let request_file = "test_data/pod_portforward.json";
        let tc = Testcase {
            name: String::from("Reject connect"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings::default(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_connect_with_exemption() -> Result<(), ()> {
        let request_file = "test_data/pod_portforward.json";

        let exempt_usernames = HashSet::from(["kubernetes-admin".to_string()]);
        let exempt_pod_names = HashSet::from(["nginx".to_string()]);
        let exempt_namespaces = HashSet::from(["default".to_string()]);

        let tc = Testcase {
            name: String::from("Exempt connect"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                exempt_usernames: Some(exempt_usernames),
                exempt_pod_names: Some(exempt_pod_names),
                exempt_namespaces: Some(exempt_namespaces),
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
