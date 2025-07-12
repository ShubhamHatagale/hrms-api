package com.opethic.hrms.HRMSNew.controllers.tranx.gstinput;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.tranx_service.gstinput.TranxGstInputService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class TranxGstInputController {

    @Autowired
    private TranxGstInputService service;

    /* get last records of voucher Contra   */
    @GetMapping(path = "/get_last_record_gstInput")
    public Object gstInputLastRecord(HttpServletRequest request) {
        JsonObject result = service.gstInputLastRecord(request);
        return result.toString();
    }

    /* Create Gst Input */
    @PostMapping(path = "/create_gst_input")
    public Object createGstInput(HttpServletRequest request) {
        JsonObject array = service.createGstInput(request);
        return array.toString();
    }


    /* Get List of GST Input   */
    @GetMapping(path = "/gst_input_list")
    public Object gstInputList(HttpServletRequest request) {
        JsonObject object = service.gstInputList(request);
        return object.toString();
    }

    /**** Update Gst Input *****/
    @PostMapping(path = "/update_gst_input")
    public Object updateGstInput(HttpServletRequest request) {
        JsonObject array = service.updateGstInput(request);
        return array.toString();
    }

    /*get GST Input by id*/
    @PostMapping(path = "/get_gst_input_by_id")
    public Object getGstInputById(HttpServletRequest request) {
        JsonObject array = service.getGstInputById(request);
        return array.toString();
    }

}
