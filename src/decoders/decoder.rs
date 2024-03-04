// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::{
    chunks::firehose::firehose_log::FirehoseItemInfo,
    decoders::{
        bool::{lowercase_bool, uppercase_bool},
        darwin::{errno_codes, permission},
        dns::{
            dns_acceptable, dns_addrmv, dns_counts, dns_getaddrinfo_opts, dns_idflags, dns_ip_addr,
            dns_protocol, dns_reason, dns_records, dns_yes_no, get_dns_mac_addr, get_domain_name,
            get_service_binding, parse_dns_header,
        },
        location::{
            client_authorization_status, client_manager_state_tracker_state, daemon_status_type,
            io_message, location_manager_state_tracker_state, sqlite, subharvester_identifier,
        },
        network::{ipv_four, ipv_six, sockaddr},
        opendirectory::{errors, member_details, member_id_type, sid_details},
        time::parse_time,
        uuid::parse_uuid,
    },
};

/// Check if we support one of Apple's custom logging objects
pub(crate) fn check_objects(
    format_string: &str,
    message_values: &[FirehoseItemInfo],
    item_type: &u8,
    item_index: usize,
) -> String {
    let mut message_value = String::new();
    let mut index = item_index;
    let precision_item = 0x12;

    // Increment index get the actual firehose item data
    if item_type == &precision_item {
        index += 1;
        if index > message_values.len() {
            return format!("Index out of bounds for FirehoseItemInfo Vec. Got adjusted index {}, Vec size is {}. This should not have happened", index, message_values.len());
        }
    }

    let masked_hash_type = 0xf2;
    // Check if the log value is hashed or marked private
    if (format_string.contains("mask.hash") && message_values[index].item_type == masked_hash_type)
        || message_values[index].message_strings == "<private>"
    {
        return message_values[index].message_strings.to_owned();
    }

    // Check if log value contains one the supported decoders
    if format_string.contains("BOOL") {
        message_value = uppercase_bool(&message_values[index].message_strings);
    } else if format_string.contains("bool") {
        message_value = lowercase_bool(&message_values[index].message_strings);
    } else if format_string.contains("uuid_t") {
        message_value = parse_uuid(&message_values[index].message_strings);
    } else if format_string.contains("darwin.errno") {
        message_value = errno_codes(&message_values[index].message_strings);
    } else if format_string.contains("darwin.mode") {
        message_value = permission(&message_values[index].message_strings);
    } else if format_string.contains("odtypes:ODError") {
        message_value = errors(&message_values[index].message_strings);
    } else if format_string.contains("odtypes:mbridtype") {
        message_value = member_id_type(&message_values[index].message_strings);
    } else if format_string.contains("odtypes:mbr_details") {
        message_value = member_details(&message_values[index].message_strings);
    } else if format_string.contains("odtypes:nt_sid_t") {
        message_value = sid_details(&message_values[index].message_strings);
    } else if format_string.contains("location:CLClientAuthorizationStatus") {
        message_value = client_authorization_status(&message_values[index].message_strings)
    } else if format_string.contains("location:CLDaemonStatus_Type::Reachability") {
        message_value = daemon_status_type(&message_values[index].message_strings);
    } else if format_string.contains("location:CLSubHarvesterIdentifier") {
        message_value = subharvester_identifier(&message_values[index].message_strings);
    } else if format_string.contains("location:SqliteResult") {
        message_value = sqlite(&message_values[index].message_strings);
    } else if format_string.contains("location:_CLClientManagerStateTrackerState") {
        message_value = client_manager_state_tracker_state(&message_values[index].message_strings);
    } else if format_string.contains("location:_CLLocationManagerStateTrackerState") {
        message_value =
            location_manager_state_tracker_state(&message_values[index].message_strings);
    } else if format_string.contains("network:in6_addr") {
        message_value = ipv_six(&message_values[index].message_strings);
    } else if format_string.contains("network:in_addr") {
        message_value = ipv_four(&message_values[index].message_strings);
    } else if format_string.contains("network:sockaddr") {
        message_value = sockaddr(&message_values[index].message_strings);
    } else if format_string.contains("time_t") {
        message_value = parse_time(&message_values[index].message_strings);
    } else if format_string.contains("mdns:dnshdr") {
        message_value = parse_dns_header(&message_values[index].message_strings);
    } else if format_string.contains("mdns:rd.svcb") {
        message_value = get_service_binding(&message_values[index].message_strings);
    } else if format_string.contains("location:IOMessage") {
        message_value = io_message(&message_values[index].message_strings);
    } else if format_string.contains("mdnsresponder:domain_name") {
        message_value = get_domain_name(&message_values[index].message_strings);
    } else if format_string.contains("mdnsresponder:mac_addr") {
        message_value = get_dns_mac_addr(&message_values[index].message_strings);
    } else if format_string.contains("mdnsresponder:ip_addr") {
        message_value = dns_ip_addr(&message_values[index].message_strings);
    } else if format_string.contains("mdns:addrmv") {
        message_value = dns_addrmv(&message_values[index].message_strings);
    } else if format_string.contains("mdns:rrtype") {
        message_value = dns_records(&message_values[index].message_strings);
    } else if format_string.contains("mdns:nreason") {
        message_value = dns_reason(&message_values[index].message_strings);
    } else if format_string.contains("mdns:protocol") {
        message_value = dns_protocol(&message_values[index].message_strings);
    } else if format_string.contains("mdns:dns.idflags") {
        message_value = dns_idflags(&message_values[index].message_strings);
    } else if format_string.contains("mdns:dns.counts") {
        message_value = dns_counts(&message_values[index].message_strings);
    } else if format_string.contains("mdns:yesno") {
        message_value = dns_yes_no(&message_values[index].message_strings);
    } else if format_string.contains("mdns:acceptable") {
        message_value = dns_acceptable(&message_values[index].message_strings);
    } else if format_string.contains("mdns:gaiopts") {
        message_value = dns_getaddrinfo_opts(&message_values[index].message_strings);
    }
    message_value
}

#[cfg(test)]
mod tests {
    use super::check_objects;
    use crate::chunks::firehose::firehose_log::FirehoseItemInfo;

    #[test]
    fn test_check_objects_lowercase_bool() {
        let test_format = "%{bool}d";
        let test_item_info = FirehoseItemInfo {
            message_strings: String::from("1"),
            item_type: 0,
            item_size: 4,
        };
        let test_type = 0;
        let test_index = 0;

        let results = check_objects(test_format, &vec![test_item_info], &test_type, test_index);
        assert_eq!(results, "true")
    }

    #[test]
    fn test_check_objects_uppercase_bool() {
        let test_format = "%{BOOL}d";
        let test_item_info = FirehoseItemInfo {
            message_strings: String::from("1"),
            item_type: 0,
            item_size: 4,
        };
        let test_type = 0;
        let test_index = 0;

        let results = check_objects(test_format, &vec![test_item_info], &test_type, test_index);
        assert_eq!(results, "YES")
    }

    #[test]
    fn test_odtypes() {
        let test_format = "%{odtypes:mbr_details}d";
        let test_item_info = FirehoseItemInfo {
            message_strings: String::from("I/7///8vTG9jYWwvRGVmYXVsdAA="),
            item_type: 50,
            item_size: 0,
        };
        let test_type = 50; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &vec![test_item_info], &test_type, test_index);
        assert_eq!(results, "user: -2@/Local/Default");
    }

    #[test]
    fn test_check_objects_uuid() {
        let test_format = "%{public,uuid_t}.16P";
        let test_item_info = FirehoseItemInfo {
            message_strings: String::from("hZV+HTbETtKGqAZXvN3ikw=="),
            item_type: 50,
            item_size: 16,
        };
        let test_type = 50; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &vec![test_item_info], &test_type, test_index);
        assert_eq!(results, "85957E1D36C44ED286A80657BCDDE293")
    }

    #[test]
    fn test_private() {
        let test_format = "%{public,uuid_t}.16P";
        let test_item_info = FirehoseItemInfo {
            message_strings: String::from("<private>"),
            item_type: 50,
            item_size: 16,
        };
        let test_type = 50; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &vec![test_item_info], &test_type, test_index);
        assert_eq!(results, "<private>")
    }

    #[test]
    fn test_hash() {
        let test_format = "%{public,mask.hash}.16P";
        let test_item_info = FirehoseItemInfo {
            message_strings: String::from("hash"),
            item_type: 242,
            item_size: 16,
        };
        let test_type = 242; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &vec![test_item_info], &test_type, test_index);
        assert_eq!(results, "hash")
    }
}
