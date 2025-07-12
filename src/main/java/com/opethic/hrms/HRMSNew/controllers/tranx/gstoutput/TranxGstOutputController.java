package com.opethic.hrms.HRMSNew.controllers.tranx.gstoutput;

import com.opethic.hrms.HRMSNew.services.tranx_service.gstoutput.TranxGstOutputService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TranxGstOutputController {
    @Autowired
    private TranxGstOutputService service;

    /* get last records of voucher Contra   */
    /*@GetMapping(path = "/get_last_record_gst_output")
    public Object gstOutputLastRecord(HttpServletRequest request) {
        JsonObject result = service.gstOutputLastRecord(request);
        return result.toString();
    }*/

    /* Create Gst Output */
   /* @PostMapping(path = "/create_gst_output")
    public Object createGstOutput(HttpServletRequest request) {
        JsonObject array = service.createGstOutput(request);
        return array.toString();
    }*/


    /* Get List of GST Output   */
    /*@GetMapping(path = "/gst_output_list")
    public Object gstOutputList(HttpServletRequest request) {
        JsonObject object = service.gstOutputList(request);
        return object.toString();
    }*/

    /**** Update Gst Output *****/
   /* @PostMapping(path = "/update_gst_output")
    public Object updateGstOutput(HttpServletRequest request) {
        JsonObject array = service.updateGstOutput(request);
        return array.toString();
    }*/

    /***** get GST Output by id *****/
    /*@PostMapping(path = "/get_gst_output_by_id")
    public Object getGstOutputById(HttpServletRequest request) {
        JsonObject array = service.getGstOutputById(request);
        return array.toString();
    }*/


}
