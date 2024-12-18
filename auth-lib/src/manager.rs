/*
 * Copyright (C) 2015-2022 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */

use afbv4::prelude::*;
use std::sync::{Mutex, MutexGuard};
use typesv4::prelude::*;

pub struct ManagerHandle {
    data_set: Mutex<AuthState>,
    event: &'static AfbEvent,
    scard_api: &'static str,
    ocpp_api: Option<&'static str>,
    engy_api: &'static str,
}

impl ManagerHandle {
    pub fn new(
        event: &'static AfbEvent,
        scard_api: &'static str,
        ocpp_api: Option<&'static str>,
        engy_api: &'static str,
    ) -> &'static mut Self {
        let handle = ManagerHandle {
            data_set: Mutex::new(AuthState::default()),
            event,
            scard_api,
            ocpp_api,
            engy_api,
        };

        // return a static handle to prevent Rust from complaining when moving/sharing it
        Box::leak(Box::new(handle))
    }

    #[track_caller]
    pub fn get_state(&self) -> Result<MutexGuard<'_, AuthState>, AfbError> {
        let guard = self.data_set.lock().unwrap();
        Ok(guard)
    }

    pub fn update_engy_state(&self, engy_state: EnergyState) -> Result<(), AfbError> {
        if self.ocpp_api.is_some() {
            AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.ocpp_api.unwrap(),
                "push-measure",
                engy_state,
            )?;
        }
        Ok(())
    }

    pub fn logout(&self, energy_session: i32) -> Result<AuthState, AfbError> {
        let mut data_set = self.get_state()?;
        match data_set.auth {
            AuthMsg::Done => {} // session is active let's logout
            AuthMsg::Fail => {}
            _ => {
                return afb_error!(
                    "auth-logout-fail",
                    "current session not authenticate status:{:?}",
                    data_set.auth
                );
            }
        }

        data_set.tagid = String::new();
        data_set.auth = AuthMsg::Idle;
        data_set.imax = 0;
        data_set.pmax = 0;
        self.event.push(data_set.auth);

        if data_set.ocpp_check && self.ocpp_api.is_some() {
            AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.engy_api,
                "state",
                EnergyAction::UNSUBSCRIBE,
            )?;

            AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.ocpp_api.unwrap(),
                "transaction",
                OcppTransaction::Stop(energy_session),
            )?;

            AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.ocpp_api.unwrap(),
                "status-notification",
                OcppChargerStatus::Available,
            )?;
        }

        Ok(data_set.clone())
    }

    pub fn login(&self) -> Result<AuthState, AfbError> {
        let mut data_set = self.get_state()?;
        match data_set.auth {
            AuthMsg::Done => {
                // we're already logged-in let handle SSO
                afb_log_msg!(
                    Notice,
                    self.event,
                    "Session Single Sign On: tagid:{}",
                    data_set.tagid
                );
                self.event.push(data_set.auth);
                return Ok(data_set.clone());
            }
            _ => {}
        }

        self.event.push(AuthMsg::Pending);
        let check_tagid = || -> Result<String, AfbError> {
            let response =
                AfbSubCall::call_sync(self.event.get_apiv4(), self.scard_api, "get-tagid", true)?;
            response.get::<String>(0)
        };

        let check_contract = || -> Result<JsoncObj, AfbError> {
            let response = AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.scard_api,
                "get-contract",
                true,
            )?;
            response.get::<JsoncObj>(0)
        };

        match check_tagid() {
            Err(error) => {
                self.event.push(AuthMsg::Fail);
                afb_log_msg!(Notice, self.event, "{}", error);
                data_set.tagid = String::new();
                data_set.auth = AuthMsg::Fail;
                return afb_error!(
                    "auth-login-fail",
                    "invalid nfc tagid authentication refused"
                );
            }
            Ok(nfc_data) => {
                data_set.tagid = nfc_data;
                data_set.imax = 32;
                data_set.pmax = 22;
                data_set.ocpp_check = true;
            }
        }

        match check_contract() {
            Err(error) => {
                self.event.push(AuthMsg::Fail);
                afb_log_msg!(Notice, self.event, "{}", error);
                data_set.tagid = String::new();
                data_set.auth = AuthMsg::Fail;
                return afb_error!("auth-login-fail", "invalid subscription contract");
            }
            Ok(jsonc) => {
                data_set.imax = jsonc.default::<u32>("imax", 32)?;
                data_set.pmax = jsonc.default::<u32>("pmax", 22)?;
                data_set.ocpp_check = jsonc.default::<bool>("ocpp", true)?;
            }
        }

        // nfc is ok let check occp tag_id
        if data_set.ocpp_check && self.ocpp_api.is_some() {
            // Badge with ocpp check

            match AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.ocpp_api.unwrap(),
                "authorize",
                data_set.tagid.clone(),
            ) {
                Ok(response) => {
                    let ocpp_state = response.get::<bool>(0)?;
                    if ocpp_state {
                        data_set.auth = AuthMsg::Done;
                        afb_log_msg!(Notice, None, "Authentication Done");
                    } else {
                        data_set.auth = AuthMsg::Fail;
                        afb_log_msg!(Notice, None, "Authentication Fail");
                        self.event.push(data_set.auth);
                        return afb_error!(
                            "ocpp-login-fail",
                            "::::::::NFC rejected by OCPP::::::::"
                        );
                    }
                }
                Err(_) => {
                    data_set.auth = AuthMsg::Fail;
                    self.event.push(data_set.auth);
                    return afb_error!(
                        "ocpp-login-fail",
                        "::::::::OCPP fails to authorize::::::::"
                    );
                }
            }

            // ocpp auth is ok let start ocpp transaction
            AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.ocpp_api.unwrap(),
                "transaction",
                OcppTransaction::Start(data_set.tagid.clone()),
            )?;

            AfbSubCall::call_sync(
                self.event.get_apiv4(),
                self.engy_api,
                "state",
                EnergyAction::SUBSCRIBE,
            )?;
        } else {
            // Badge without ocpp check
            data_set.auth = AuthMsg::Done;
            afb_log_msg!(Notice, None, "Authentification Done");
        }
        self.event.push(data_set.auth);
        Ok(data_set.clone())
    }
}
