// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::DecoderError;
use crate::{decoders::bool::bool_from_int, util::decode_standard};
use log::warn;
use nom::{
    IResult, Parser,
    bytes::complete::take,
    number::complete::{le_f64, le_i32, le_i64, le_u8, le_u32},
};
use std::fmt::Display;

#[derive(Debug, Default)]
pub struct LocationTrackerState {
    distance_filter: f64,
    desired_accuracy: f64,
    updating_location: u8,
    requesting_location: u8,
    requesting_ranging: u8,
    updating_ranging: u8,
    updating_heading: u8,
    heading_filter: f64,
    allows_location_prompts: u8,
    allows_altered_locations: u8,
    dynamic_accuracy: u8,
    previous_authorization_status_valid: u8,
    previous_authorization_status: i32,
    limits_precision: u8,
    activity_type: i64,
    pauses_location_updates: i32,
    paused: u8,
    allows_background_updates: u8,
    shows_background_location: u8,
    allows_map_correction: u8,
    batching_location: u8,
    updating_vehicle_speed: u8,
    updating_vehicle_heading: u8,
    match_info: u8,
    ground_altitude: u8,
    fusion_info: u8,
    courtesy_prompt: u8,
    is_authorized_for_widgets: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum ClientAuthorizationStatus {
    #[strum(to_string = "Not Determined")]
    NotDetermined,
    #[strum(to_string = "Restricted")]
    Restricted,
    #[strum(to_string = "Denied")]
    Denied,
    #[strum(to_string = "Authorized Always")]
    AuthorizedAlways,
    #[strum(to_string = "Authorized When In Use")]
    AuthorizedWhenInUse,
}

/// Convert Core Location Client Autherization Status code to string
pub(crate) fn client_authorization_status(
    status: &str,
) -> Result<ClientAuthorizationStatus, DecoderError<'_>> {
    match status {
        "0" => Ok(ClientAuthorizationStatus::NotDetermined),
        "1" => Ok(ClientAuthorizationStatus::Restricted),
        "2" => Ok(ClientAuthorizationStatus::Denied),
        "3" => Ok(ClientAuthorizationStatus::AuthorizedAlways),
        "4" => Ok(ClientAuthorizationStatus::AuthorizedWhenInUse),
        _ => Err(DecoderError::Parse {
            input: status.as_bytes(),
            parser_name: "client authorization status",
            message: "Unknown Core Location client authorization status",
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum DaemonStatusType {
    #[strum(to_string = "Reachability Unavailable")]
    ReachabilityUnavailable,
    #[strum(to_string = "Reachability Small")]
    ReachabilitySmall,
    #[strum(to_string = "Reachability Large")]
    ReachabilityLarge,
    #[strum(to_string = "Reachability Unachievable")]
    ReachabilityUnachievable,
}

/// Convert Core Location Daemon Status type to string
pub(crate) fn daemon_status_type(status: &str) -> Result<DaemonStatusType, DecoderError<'_>> {
    // Found in dyldcache liblog
    match status {
        "0" => Ok(DaemonStatusType::ReachabilityUnavailable),
        "1" => Ok(DaemonStatusType::ReachabilitySmall),
        "2" => Ok(DaemonStatusType::ReachabilityLarge),
        "56" => Ok(DaemonStatusType::ReachabilityUnachievable),
        _ => Err(DecoderError::Parse {
            input: status.as_bytes(),
            parser_name: "daemon status type",
            message: "Unknown Core Location daemon status type",
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum SubharvesterIdentifier {
    #[strum(to_string = "CellLegacy")]
    CellLegacy,
    #[strum(to_string = "Cell")]
    Cell,
    #[strum(to_string = "Wifi")]
    Wifi,
    #[strum(to_string = "Tracks")]
    Tracks,
    #[strum(to_string = "Realtime")]
    Realtime,
    #[strum(to_string = "App")]
    App,
    #[strum(to_string = "Pass")]
    Pass,
    #[strum(to_string = "Indoor")]
    Indoor,
    #[strum(to_string = "Pressure")]
    Pressure,
    #[strum(to_string = "Poi")]
    Poi,
    #[strum(to_string = "Trace")]
    Trace,
    #[strum(to_string = "Avenger")]
    Avenger,
    #[strum(to_string = "Altimeter")]
    Altimeter,
    #[strum(to_string = "Ionosphere")]
    Ionosphere,
    #[strum(to_string = "Unknown")]
    Unknown,
}

/// Convert Core Location Subhaverester id to string
pub(crate) fn subharvester_identifier(
    status: &str,
) -> Result<SubharvesterIdentifier, DecoderError<'_>> {
    // Found in dyldcache liblog
    match status {
        "0" => Ok(SubharvesterIdentifier::CellLegacy),
        "1" => Ok(SubharvesterIdentifier::Cell),
        "2" => Ok(SubharvesterIdentifier::Wifi),
        "3" => Ok(SubharvesterIdentifier::Tracks),
        "4" => Ok(SubharvesterIdentifier::Realtime),
        "5" => Ok(SubharvesterIdentifier::App),
        "6" => Ok(SubharvesterIdentifier::Pass),
        "7" => Ok(SubharvesterIdentifier::Indoor),
        "8" => Ok(SubharvesterIdentifier::Pressure),
        "9" => Ok(SubharvesterIdentifier::Poi),
        "10" => Ok(SubharvesterIdentifier::Trace),
        "11" => Ok(SubharvesterIdentifier::Avenger),
        "12" => Ok(SubharvesterIdentifier::Altimeter),
        "13" => Ok(SubharvesterIdentifier::Ionosphere),
        "14" => Ok(SubharvesterIdentifier::Unknown),
        _ => Err(DecoderError::Parse {
            input: status.as_bytes(),
            parser_name: "subharvester identifier",
            message: "Unknown Core Location subhaverster identifier type",
        }),
    }
}

/// Convert Core Location SQLITE code to string
pub(crate) fn sqlite_location(input: &str) -> Result<SqliteError, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "sqlite location",
        message: "Failed to base64 decode sqlite details",
    })?;

    let (_, result) = get_sqlite_data(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "sqlite location",
        message: "Failed to get sqlite error",
    })?;

    Ok(result)
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum SqliteError {
    #[strum(to_string = "SQLITE OK")]
    SQLITE_OK,
    #[strum(to_string = "SQLITE ERROR")]
    SQLITE_ERROR,
    #[strum(to_string = "SQLITE INTERNAL")]
    SQLITE_INTERNAL,
    #[strum(to_string = "SQLITE PERM")]
    SQLITE_PERM,
    #[strum(to_string = "SQLITE ABORT")]
    SQLITE_ABORT,
    #[strum(to_string = "SQLITE BUSY")]
    SQLITE_BUSY,
    #[strum(to_string = "SQLITE LOCKED")]
    SQLITE_LOCKED,
    #[strum(to_string = "SQLITE NOMEM")]
    SQLITE_NOMEM,
    #[strum(to_string = "SQLITE READ ONLY")]
    SQLITE_READ_ONLY,
    #[strum(to_string = "SQLITE INTERRUPT")]
    SQLITE_INTERRUPT,
    #[strum(to_string = "SQLITE IO ERR")]
    SQLITE_IO_ERR,
    #[strum(to_string = "SQLITE CORRUPT")]
    SQLITE_CORRUPT,
    #[strum(to_string = "SQLITE NOT FOUND")]
    SQLITE_NOT_FOUND,
    #[strum(to_string = "SQLITE FULL")]
    SQLITE_FULL,
    #[strum(to_string = "SQLITE CAN'T OPEN")]
    SQLITE_CANT_OPEN,
    #[strum(to_string = "SQLITE PROTOCOL")]
    SQLITE_PROTOCOL,
    #[strum(to_string = "SQLITE EMPTY")]
    SQLITE_EMPTY,
    #[strum(to_string = "SQLITE SCHEMA")]
    SQLITE_SCHEMA,
    #[strum(to_string = "SQLITE TOO BIG")]
    SQLITE_TOO_BIG,
    #[strum(to_string = "SQLITE CONSTRAINT")]
    SQLITE_CONSTRAINT,
    #[strum(to_string = "SQLITE MISMATCH")]
    SQLITE_MISMATCH,
    #[strum(to_string = "SQLITE MISUSE")]
    SQLITE_MISUSE,
    #[strum(to_string = "SQLITE NO LFS")]
    SQLITE_NO_LFS,
    #[strum(to_string = "SQLITE AUTH")]
    SQLITE_AUTH,
    #[strum(to_string = "SQLITE FORMAT")]
    SQLITE_FORMAT,
    #[strum(to_string = "SQLITE RANGE")]
    SQLITE_RANGE,
    #[strum(to_string = "SQLITE NOT A DB")]
    SQLITE_NOT_A_DB,
    #[strum(to_string = "SQLITE NOTICE")]
    SQLITE_NOTICE,
    #[strum(to_string = "SQLITE WARNING")]
    SQLITE_WARNING,
    #[strum(to_string = "SQLITE ROW")]
    SQLITE_ROW,
    #[strum(to_string = "SQLITE DONE")]
    SQLITE_DONE,
    #[strum(to_string = "SQLITE IO ERR READ")]
    SQLITE_IO_ERR_READ,
    #[strum(to_string = "Unknown Core Location sqlite error")]
    Unknown,
}

/// Get the SQLITE error message
fn get_sqlite_data(input: &[u8]) -> IResult<&[u8], SqliteError> {
    let (input, sqlite_code) = le_u32(input)?;
    // Found at https://www.sqlite.org/rescode.html
    let result = match sqlite_code {
        0 => SqliteError::SQLITE_OK,
        1 => SqliteError::SQLITE_ERROR,
        2 => SqliteError::SQLITE_INTERNAL,
        3 => SqliteError::SQLITE_PERM,
        4 => SqliteError::SQLITE_ABORT,
        5 => SqliteError::SQLITE_BUSY,
        6 => SqliteError::SQLITE_LOCKED,
        7 => SqliteError::SQLITE_NOMEM,
        8 => SqliteError::SQLITE_READ_ONLY,
        9 => SqliteError::SQLITE_INTERRUPT,
        10 => SqliteError::SQLITE_IO_ERR,
        11 => SqliteError::SQLITE_CORRUPT,
        12 => SqliteError::SQLITE_NOT_FOUND,
        13 => SqliteError::SQLITE_FULL,
        14 => SqliteError::SQLITE_CANT_OPEN,
        15 => SqliteError::SQLITE_PROTOCOL,
        16 => SqliteError::SQLITE_EMPTY,
        17 => SqliteError::SQLITE_SCHEMA,
        18 => SqliteError::SQLITE_TOO_BIG,
        19 => SqliteError::SQLITE_CONSTRAINT,
        20 => SqliteError::SQLITE_MISMATCH,
        21 => SqliteError::SQLITE_MISUSE,
        22 => SqliteError::SQLITE_NO_LFS,
        23 => SqliteError::SQLITE_AUTH,
        24 => SqliteError::SQLITE_FORMAT,
        25 => SqliteError::SQLITE_RANGE,
        26 => SqliteError::SQLITE_NOT_A_DB,
        27 => SqliteError::SQLITE_NOTICE,
        28 => SqliteError::SQLITE_WARNING,
        100 => SqliteError::SQLITE_ROW,
        101 => SqliteError::SQLITE_DONE,
        266 => SqliteError::SQLITE_IO_ERR_READ,
        _ => {
            warn!("[macos-unifiedlogs] Unknown Core Location sqlite error: {sqlite_code}");
            SqliteError::Unknown
        }
    };
    Ok((input, result))
}

/// Parse the manager tracker state data
pub(crate) fn client_manager_state_tracker_state(
    input: &str,
) -> Result<LocationStateTrackerData, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "client manager state tracker state",
        message: "Failed to base64 decode client manager tracker state",
    })?;

    let (_, result) = get_state_tracker_data(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "client manager state tracker state",
        message: "Failed to get client tracker data",
    })?;

    Ok(result)
}

pub struct LocationStateTrackerData {
    location_enabled: u32,
    location_restricted: u32,
}

impl Display for LocationStateTrackerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\"locationRestricted\":{}, \"locationServicesenabledStatus\":{}}}",
            bool_from_int(self.location_restricted),
            self.location_enabled
        )
    }
}

/// Get the tracker data
pub(crate) fn get_state_tracker_data(input: &[u8]) -> IResult<&[u8], LocationStateTrackerData> {
    let mut tup = (le_u32, le_u32);
    let (input, (location_enabled, location_restricted)) = tup.parse(input)?;
    Ok((
        input,
        LocationStateTrackerData {
            location_enabled,
            location_restricted,
        },
    ))
}

/// Parse location tracker state data
pub(crate) fn location_manager_state_tracker_state(
    input: &str,
) -> Result<LocationTrackerState, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "location manager state tracker state",
        message: "Failed to base64 decode logon manager trackder data",
    })?;

    let (_, result) =
        get_location_tracker_state(&decoded_data).map_err(|_| DecoderError::Parse {
            input: input.as_bytes(),
            parser_name: "location manager state tracker state",
            message: "Failed to get logon manager tracker data",
        })?;

    Ok(result)
}

/// Get the location state data
pub(crate) fn get_location_tracker_state(
    input: &[u8],
) -> nom::IResult<&[u8], LocationTrackerState> {
    // https://github.com/cmsj/ApplePrivateHeaders/blob/main/macOS/11.3/System/Library/Frameworks/CoreLocation.framework/Versions/A/CoreLocation/CoreLocation-Structs.h and in dyldcache

    // Padding? Reserved?
    const UNKNOWN_DATA_LENGTH: usize = 3;
    // padding? Reserved?
    const UNKONWN_DATA_LENGTH2: usize = 7;

    let mut accuracy_tup = (le_f64, le_f64, le_u8, le_u8, le_u8, le_u8, le_u8);
    let (
        input,
        (
            distance_filter,
            desired_accuracy,
            updating_location,
            requesting_location,
            requesting_ranging,
            updating_ranging,
            updating_heading,
        ),
    ) = accuracy_tup.parse(input)?;

    let mut dynamic_tup = (take(UNKNOWN_DATA_LENGTH), le_f64, le_u8, le_u8, le_u8);
    let (
        input,
        (
            _unknown,
            heading_filter,
            allows_location_prompts,
            allows_altered_locations,
            dynamic_accuracy,
        ),
    ) = dynamic_tup.parse(input)?;

    let mut track_tup = (
        le_u8,
        le_i32,
        le_u8,
        take(UNKONWN_DATA_LENGTH2),
        le_i64,
        le_i32,
    );
    let (
        input,
        (
            previous_authorization_status_valid,
            previous_authorization_status,
            limits_precision,
            _unknown2,
            activity_type,
            pauses_location_updates,
        ),
    ) = track_tup.parse(input)?;

    let mut back_tup = (le_u8, le_u8, le_u8, le_u8);
    let (
        input,
        (paused, allows_background_updates, shows_background_location, allows_map_correction),
    ) = back_tup.parse(input)?;

    let location_data = input;

    let tracker = LocationTrackerState {
        distance_filter,
        desired_accuracy,
        updating_location,
        requesting_location,
        requesting_ranging,
        updating_ranging,
        updating_heading,
        heading_filter,
        allows_location_prompts,
        allows_altered_locations,
        dynamic_accuracy,
        previous_authorization_status_valid,
        previous_authorization_status,
        limits_precision,
        activity_type,
        pauses_location_updates,
        paused,
        allows_background_updates,
        shows_background_location,
        allows_map_correction,
        ..Default::default()
    };

    // Sometimes location data only has 64 bytes of data. Seen only on Catalina. Though this might be a setting configuration?
    // All other systems have 72 bytes of location data even systems before Catalina (ex: Mojave)
    // Return early if we only have 64 bytes to work with
    const CATALINA_SIZE: usize = 64;
    if input.len() == CATALINA_SIZE {
        return Ok((location_data, tracker));
    }

    let mut location_tup = (le_u8, le_u8, le_u8, le_u8, le_u8, le_u8, le_u8, le_u8);
    let (
        input,
        (
            batching_location,
            updating_vehicle_speed,
            updating_vehicle_heading,
            match_info,
            ground_altitude,
            fusion_info,
            courtesy_prompt,
            is_authorized_for_widgets,
        ),
    ) = location_tup.parse(input)?;

    let tracker = LocationTrackerState {
        batching_location,
        updating_vehicle_speed,
        updating_vehicle_heading,
        match_info,
        ground_altitude,
        fusion_info,
        courtesy_prompt,
        is_authorized_for_widgets,
        ..tracker
    };

    Ok((input, tracker))
}

/// Create the location tracker json object
impl Display for LocationTrackerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{
            \"distanceFilter\":{}, 
            \"desiredAccuracy\":{}, 
            \"updatingLocation\":{}, 
            \"requestingLocation\":{}, 
            \"requestingRanging\":{}, 
            \"updatingRanging\":{},
            \"updatingHeading\":{},
            \"headingFilter\":{},
            \"allowsLocationPrompts\":{},
            \"allowsAlteredAccessoryLocations\":{},
            \"dynamicAccuracyReductionEnabled\":{},
            \"previousAuthorizationStatusValid\":{},
            \"previousAuthorizationStatus\":{},
            \"limitsPrecision\":{},
            \"activityType\":{},
            \"pausesLocationUpdatesAutomatically\":{},
            \"paused\":{},
            \"allowsBackgroundLocationUpdates\":{},
            \"showsBackgroundLocationIndicator\":{},
            \"allowsMapCorrection\":{},
            \"batchingLocation\":{},
            \"updatingVehicleSpeed\":{},
            \"updatingVehicleHeading\":{},
            \"matchInfoEnabled\":{},
            \"groundAltitudeEnabled\":{},
            \"fusionInfoEnabled\":{},
            \"courtesyPromptNeeded\":{},
            \"isAuthorizedForWidgetUpdates\":{},
        }}",
            self.distance_filter,
            self.desired_accuracy,
            bool_from_int(self.updating_location),
            bool_from_int(self.requesting_location),
            bool_from_int(self.requesting_ranging),
            bool_from_int(self.updating_ranging),
            bool_from_int(self.updating_heading),
            self.heading_filter,
            bool_from_int(self.allows_location_prompts),
            bool_from_int(self.allows_altered_locations),
            bool_from_int(self.dynamic_accuracy),
            bool_from_int(self.previous_authorization_status_valid),
            self.previous_authorization_status,
            bool_from_int(self.limits_precision),
            self.activity_type,
            self.pauses_location_updates,
            bool_from_int(self.paused),
            bool_from_int(self.allows_background_updates),
            bool_from_int(self.shows_background_location),
            bool_from_int(self.allows_map_correction),
            bool_from_int(self.batching_location),
            bool_from_int(self.updating_vehicle_speed),
            bool_from_int(self.updating_vehicle_heading),
            bool_from_int(self.match_info),
            bool_from_int(self.ground_altitude),
            bool_from_int(self.fusion_info),
            bool_from_int(self.courtesy_prompt),
            bool_from_int(self.is_authorized_for_widgets),
        )
    }
}

/// Parse location tracker state data
pub(crate) fn io_message(data: &str) -> Result<&'static str, DecoderError<'_>> {
    // Found in dyldcache
    let message = match data {
        "3758097008" => "CanSystemSleep",
        "3758097024" => "SystemWillSleep",
        "3758097040" => "SystemWillNotSleep",
        "3758097184" => "SystemWillPowerOn",
        "3758097168" => "SystemWillRestart",
        "3758097152" => "SystemHasPoweredOn",
        "3758097200" => "CopyClientID",
        "3758097216" => "SystemCapabilityChange",
        "3758097232" => "DeviceSignaledWakeup",
        "3758096400" => "ServiceIsTerminated",
        "3758096416" => "ServiceIsSuspended",
        "3758096432" => "ServiceIsResumed",
        "3758096640" => "ServiceIsRequestingClose",
        "3758096641" => "ServiceIsAttemptingOpen",
        "3758096656" => "ServiceWasClosed",
        "3758096672" => "ServiceBusyStateChange",
        "3758096680" => "ConsoleSecurityChange",
        "3758096688" => "ServicePropertyChange",
        "3758096896" => "CanDevicePowerOff",
        "3758096912" => "DeviceWillPowerOff",
        "3758096928" => "DeviceWillNotPowerOff",
        "3758096944" => "DeviceHasPoweredOn",
        "3758096976" => "SystemWillPowerOff",
        "3758096981" => "SystemPagingOff",
        _ => {
            return Err(DecoderError::Parse {
                input: data.as_bytes(),
                parser_name: "io message",
                message: "Unknown IO Message",
            });
        }
    };
    Ok(message)
}

pub struct DaemonTrackerData {
    level: f64,
    charged: u8,
    connected: u8,
    _unknown: u8,
    _unknown2: u8,
    charger_type: ChargerType,
    _unknown3: u32,
    _unknown4: u32,
    reachability: ReachabilityStatus,
    thermal_level: i32,
    airplane: u8,
    battery_saver: u8,
    push_service: u8,
    restricted: u8,
    was_connected: bool,
}

impl Display for DaemonTrackerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"{{"thermalLevel": {}, "reachability": "{}", "airplaneMode": {}, "batteryData":{{"wasConnected": {}, "charged": {}, "level": {}, "connected": {}, "chargerType": "{}"}}, "restrictedMode": {}, "batterySaverModeEnabled": {}, "push_service":{}}}"#,
            self.thermal_level,
            self.reachability,
            bool_from_int(self.airplane),
            self.was_connected,
            bool_from_int(self.charged),
            self.level,
            bool_from_int(self.connected),
            self.charger_type,
            bool_from_int(self.restricted),
            bool_from_int(self.battery_saver),
            bool_from_int(self.push_service)
        )
    }
}

/// Values found in dyldcache logd_location
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum ReachabilityStatus {
    #[strum(to_string = "kReachabilityUnavailable")]
    Unavailable,
    #[strum(to_string = "kReachabilitySmall")]
    Small,
    #[strum(to_string = "kReachabilityLarge")]
    Large,
    #[strum(to_string = "kReachabilityUnachievable")]
    Unachievable,
    #[strum(to_string = "Unknown Reachability Status {0}")]
    Unknown(u32),
}

impl From<u32> for ReachabilityStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => ReachabilityStatus::Unavailable,
            1 => ReachabilityStatus::Small,
            2 => ReachabilityStatus::Large,
            1000 => ReachabilityStatus::Unachievable,
            _ => ReachabilityStatus::Unknown(value),
        }
    }
}

// Values found in dyldcache logd_location
// Other values seen are:
// kChargerTypeNone, kChargerTypeExternal, and kChargerTypeArcas.
// But have not observed the numerical value for these types
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum ChargerType {
    #[strum(to_string = "kChargerTypeUnknown")]
    Unknown,
    #[strum(to_string = "kChargerTypeUsb")]
    Usb,
    #[strum(to_string = "Unknown charger type value {0}")]
    Other(u32),
}

impl From<u32> for ChargerType {
    fn from(value: u32) -> Self {
        match value {
            0 => ChargerType::Unknown,
            2 => ChargerType::Usb,
            _ => ChargerType::Other(value),
        }
    }
}

/// Parse and get the location Daemon tracker
pub(crate) fn get_daemon_status_tracker(input: &[u8]) -> nom::IResult<&[u8], DaemonTrackerData> {
    // Slightly outdated but still helpful: https://gist.github.com/razvand/578f94748b624f4d47c1533f5a02b095
    let mut tup = (
        le_f64, le_u8, le_u8, le_u8, le_u8, le_u32, le_u32, le_u32, le_u32, le_i32, le_u8, le_u8,
        le_u8, le_u8,
    );
    let (
        location_data,
        (
            level,
            charged,
            connected,
            _unknown,
            _unknown2,
            charger_type,
            _unknown3,
            _unknown4,
            reachability,
            thermal_level,
            airplane,
            battery_saver,
            push_service,
            restricted,
        ),
    ) = tup.parse(input)?;

    // When these unknown values are not 0 `was_connected` is always true
    // Not 100% sure the significance or what they represent
    let was_connected = _unknown != 0 && _unknown2 != 0 && _unknown3 != 0;

    let charger_type: ChargerType = charger_type.into();
    let reachability: ReachabilityStatus = reachability.into();

    let tracker_data = DaemonTrackerData {
        level,
        charged,
        connected,
        _unknown,
        _unknown2,
        charger_type,
        _unknown3,
        _unknown4,
        reachability,
        thermal_level,
        airplane,
        battery_saver,
        push_service,
        restricted,
        was_connected,
    };

    Ok((location_data, tracker_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::decode_standard;

    #[test]
    fn test_client_authorization_status() {
        let test_data = "0";
        let result = client_authorization_status(test_data).unwrap();
        assert_eq!(result, ClientAuthorizationStatus::NotDetermined)
    }

    #[test]
    fn test_daemon_status_type() {
        let test_data = "2";
        let result = daemon_status_type(test_data).unwrap();

        assert_eq!(result, DaemonStatusType::ReachabilityLarge)
    }

    #[test]
    fn test_subharvester_identifier() {
        let test_data = "2";
        let result = subharvester_identifier(test_data).unwrap();

        assert_eq!(result, SubharvesterIdentifier::Wifi)
    }

    #[test]
    fn test_sqlite() {
        let test_data = "AAAAAA==";
        let result = sqlite_location(test_data).unwrap();

        assert_eq!(result, SqliteError::SQLITE_OK)
    }

    #[test]
    fn test_get_sqlite_data() {
        let test_data = "AAAAAA==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_sqlite_data(&decoded_data_result).unwrap();

        assert_eq!(result, SqliteError::SQLITE_OK)
    }

    #[test]
    fn test_client_manager_state_tracker_state() {
        let test_data = "AQAAAAAAAAA=";
        let result = client_manager_state_tracker_state(test_data).unwrap();

        assert_eq!(
            result.to_string(),
            "{\"locationRestricted\":false, \"locationServicesenabledStatus\":1}"
        )
    }

    #[test]
    fn test_location_tracker_object() {
        let test_data = LocationTrackerState::default();
        assert_eq!(
            test_data.to_string(),
            "{\n            \"distanceFilter\":0, \n            \"desiredAccuracy\":0, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":0,\n            \"allowsLocationPrompts\":false,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":0,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":false,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"
        )
    }

    #[test]
    fn test_get_state_tracker_data() {
        let test_data = "AQAAAAAAAAA=";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_state_tracker_data(&decoded_data_result).unwrap();

        assert_eq!(
            result.to_string(),
            "{\"locationRestricted\":false, \"locationServicesenabledStatus\":1}"
        )
    }

    #[test]
    fn test_location_manager_state_tracker_state() {
        let test_data = "AAAAAAAA8L8AAAAAAABZQAAAAAAAAAAAAAAAAAAA8D8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAA";
        let result = location_manager_state_tracker_state(test_data).unwrap();

        assert_eq!(
            result.to_string(),
            "{\n            \"distanceFilter\":-1, \n            \"desiredAccuracy\":100, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":1,\n            \"allowsLocationPrompts\":true,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":1,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":true,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"
        )
    }

    #[test]
    fn test_get_location_tracker_state() {
        let test_data = "AAAAAAAA8L8AAAAAAABZQAAAAAAAAAAAAAAAAAAA8D8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAA";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_location_tracker_state(&decoded_data_result).unwrap();

        assert_eq!(
            result.to_string(),
            "{\n            \"distanceFilter\":-1, \n            \"desiredAccuracy\":100, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":1,\n            \"allowsLocationPrompts\":true,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":1,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":true,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"
        )
    }

    #[test]
    fn test_io_message() {
        let test_data = "3758096981";
        let result = io_message(test_data).unwrap();
        assert_eq!(result, "SystemPagingOff")
    }

    #[test]
    fn test_get_daemon_status_tracker() {
        let test_data = [
            0, 0, 0, 0, 0, 0, 240, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
            255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (_, result) = get_daemon_status_tracker(&test_data).unwrap();

        assert_eq!(
            result.to_string(),
            "{\"thermalLevel\": -1, \"reachability\": \"kReachabilityLarge\", \"airplaneMode\": false, \"batteryData\":{\"wasConnected\": false, \"charged\": false, \"level\": -1, \"connected\": false, \"chargerType\": \"kChargerTypeUnknown\"}, \"restrictedMode\": false, \"batterySaverModeEnabled\": false, \"push_service\":false}"
        )
    }

    #[test]
    fn test_get_daemon_status_tracker_was_connected_true() {
        let test_data = [
            0, 0, 0, 0, 0, 0, 89, 64, 0, 1, 19, 4, 2, 0, 0, 0, 1, 192, 243, 246, 5, 64, 0, 224, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (_, result) = get_daemon_status_tracker(&test_data).unwrap();

        assert_eq!(
            result.to_string(),
            "{\"thermalLevel\": 0, \"reachability\": \"kReachabilityLarge\", \"airplaneMode\": false, \"batteryData\":{\"wasConnected\": true, \"charged\": false, \"level\": 100, \"connected\": true, \"chargerType\": \"kChargerTypeUsb\"}, \"restrictedMode\": false, \"batterySaverModeEnabled\": false, \"push_service\":false}"
        )
    }
}
