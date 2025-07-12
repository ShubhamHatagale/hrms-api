package com.opethic.hrms.HRMSNew.controllers.config;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.config.AppConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class AppConfigController {
    @Autowired
    private AppConfigService service;
    @PostMapping(path = "/create_app_config")
    public ResponseEntity<?> addConfig(HttpServletRequest request) {
        return ResponseEntity.ok(service.addConfig(request));
    }
    /* update App Config by id*/
    @PostMapping(path = "/update_app_config")
    public Object updateConfig(HttpServletRequest request) {
        JsonObject result = service.updateConfig(request);
        return result.toString();
    }
    /* Get all App Config of Company */
    @GetMapping(path = "/get_company_appConfig")
    public Object getAllCompanyAppConfig(HttpServletRequest request) {
        JsonObject result = service.getAllCompanyAppConfig(request);
        return result.toString();
    }
   /**** get AppConfig by Id */
    @PostMapping(path = "/get_appConfig_by_id")
    public Object getappConfigById(HttpServletRequest request) {
        JsonObject result = service.getappConfigById(request);
        return result.toString();
    }
    /*** Removal of App Config ****/
    @PostMapping(path="/remove_appConfig")
    public Object removeAppConfig(HttpServletRequest request)
    {
        JsonObject result=service.removeAppConfig(request);
        return result.toString();
    }

    /*** Get all Master System Configuration of App Config ****/
    @PostMapping(path="/get_all_master_system_config")
    public Object getMasterSystemAppConfig(HttpServletRequest request)
    {
        JsonObject result=service.getMasterSystemAppConfig(request);
        return result.toString();
    }


}
