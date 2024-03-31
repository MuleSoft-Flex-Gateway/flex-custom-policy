use log::info;
//developer: srikanth.kusumba
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use jwt_simple::prelude::*;
use jwt_simple::prelude::RS256PublicKey;
use jwt_simple::prelude::RS384PublicKey;
//use serde::{Deserialize, Serialize}; //un used import Serialize
use serde::Deserialize;
use serde::de::IntoDeserializer;
use std::str;


proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CustomAuthRootContext {
            config: CustomAuthConfig::default(),
        })
    });
}}

struct CustomAuthRootContext {
    config: CustomAuthConfig,
}

impl Context for CustomAuthRootContext {}

impl RootContext for CustomAuthRootContext {

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CustomAuthHttpContext {
            config: self.config.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            self.config = serde_json::from_slice(config_bytes.as_slice()).unwrap();
        }

        true
    }

    // Other implemented methods
    // ...
}

#[derive(Default, Clone, Deserialize)]
struct CustomAuthConfig {

    #[serde(alias = "jwt-origin")]
    secret_value: String
}

struct CustomAuthHttpContext {
    pub config: CustomAuthConfig,
}

impl Context for CustomAuthHttpContext {
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        log::info!("------------------2. inside on_http_call_response -------------------");

        let body_op = self.get_http_call_response_body(0, body_size);

        if read_session_body_bool(body_op){
            print!("-------------------4. token succcessfully validated -------------------");
            self.resume_http_request();
        }
        else {
            self.send_http_response(
                403,
                vec![("outbound-response-header", "invalid-token")],
                Some(b"access forbidden.\n"),
            );
        }
        
        self.resume_http_request();

    }
}

impl HttpContext for CustomAuthHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        println!("selected auth header is {}",self.config.secret_value);
        let _jwt_origin = self.config.secret_value.to_ascii_lowercase();

        let mut _jwt_origin_header = "Authorization";//default request header to look for is Authorization: Bearer {token value}
        if _jwt_origin=="jwt"
        {
            _jwt_origin_header = "jwt";
        }
        else {
            _jwt_origin_header="Authorization";
        }

        log::info!("------------------jwt origin choosen in policy:{} ----------------",_jwt_origin_header);

        if let Some(_jwt_token) = self.get_http_request_header(_jwt_origin_header){
            
            //outbound service call
            let token_str = "{\"token\":\"TOKEN\"}";
            let token_object = token_str.replace("TOKEN",&_jwt_token );
            
            log::info!("------------------payload token:{} ----------------",token_object);

            let request_body = token_object.as_str().as_bytes();

            match self.dispatch_http_call(
                "muleflexapi.gateway.svc",
                  vec![
                      (":method", "POST"),
                      (":path", "/as/introspect.oauth2"),
                      (":authority", "mule-flex-api.mulesoft-rtf-dev-app.svc"),//mulesoft-rtf-dev-app is the namespace where muleflexapi pod is deployed
                      //scheme is http for pod to pod
                      (":scheme", "http"),
                      ("content-type", "application/json"),
                  ],
                  Some(request_body),
                  vec![],
                  std::time::Duration::from_secs(10),
              ){
                    Ok(resp) => {log::info!("----------------1. muleflexapi invocation succedded---------------- {}",resp)},
                    Err(err) => log::info!("---------------- ERROR in muleflexapi invocation custom policy: {:?}",err)
                };
            
            return Action::Pause;
        }
        
        self.send_http_response(401, Vec::new(), None);
        Action::Pause
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        //can inject custom headers here
        //self.set_http_response_header("custom-header-key", Some("custom-header-value"));
        //log::info!("custom-header injected");
        Action::Continue
    }
    
    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        log::info!("-------------END. inside on_http_response_body-------------------");
        if !end_of_stream {
            // Wait -- we'll be called again when the complete body is buffered
            // at the host side.
            return Action::Pause;
        }

        // modify response bod here - if required

        // Replace the message body if it contains the text "secret".
        // Since we returned "Pause" previuously, this will return the whole body.
        // if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
        //     let _body_str = String::from_utf8(body_bytes).unwrap();
        //     log::info!("response body: {}",_body_str);
        //     if _body_str.contains("token") {
        //         log::info!("v6 response contains token");
        //          //     let new_body = format!("Original message body ({body_size} bytes) redacted.\n");
        //          //     self.set_http_response_body(0, body_size, &new_body.into_bytes());
        //      }
        // }
        Action::Continue
    }

}

pub fn read_session_body_bool(body_op: Option<Bytes>) -> bool{
    log::info!("---------- 3. validating response session ---------------------");
    if let Some(body) = body_op {
        let json = str::from_utf8(&body).unwrap();
        info!(" --------------- token valid? = {}--------------- ",json);
        if json=="true"{
            return true;
        }
    }
    return false;
}
