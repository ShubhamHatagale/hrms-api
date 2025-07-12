package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.AreaMasterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class AreaMasterController {
    @Autowired
    private AreaMasterService areaMasterService;

    @PostMapping(path = "/create_area_master")
    public ResponseEntity<?> createAreaMaster(HttpServletRequest request) {
        return ResponseEntity.ok(areaMasterService.createAreaMaster(request));
    }

    /* Get all Area Master of Outlets */
    @GetMapping(path = "/get_outlet_area_master")
    public Object getAllAreaMaster(HttpServletRequest request) {
        JsonObject result = areaMasterService.getAllAreaMaster(request);
        return result.toString();
    }

    /* get Area Master by Id */
    @PostMapping(path = "/get_area_master_by_id")
    public Object getAreaMaster(HttpServletRequest request) {
        JsonObject result = areaMasterService.getAreaMaster(request);
        return result.toString();
    }
    @PostMapping(path = "/update_area_master")
    public Object updateAreaMaster(HttpServletRequest request) {
        JsonObject result = areaMasterService.updateAreaMaster(request);
        return result.toString();
    }
    @PostMapping(path = "/remove_area_master")
    public Object removeAreaMaster(HttpServletRequest request) {
        JsonObject result = areaMasterService.removeAreaMaster(request);
        return result.toString();
    }
}
