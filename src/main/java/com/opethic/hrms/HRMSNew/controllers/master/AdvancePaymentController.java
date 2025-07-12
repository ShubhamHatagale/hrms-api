package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.AdvancePaymentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class AdvancePaymentController {
    @Autowired
    private AdvancePaymentService advancePaymentService;

    /*Mobile app urls start*/
    @PostMapping(path = "/mobile/createAdvancePaymentRequest")
    public Object createAdvancePaymentRequest(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return advancePaymentService.createAdvancePaymentRequest(requestParam, request);
    }

    @GetMapping(path = "/mobile/advancePaymentDashboard")
    public Object advancePaymentDashboard(HttpServletRequest request) {
        JsonObject res = advancePaymentService.advancePaymentDashboard(request);
        return res.toString();
    }

    @GetMapping(path = "/mobile/listOfAdvancePayment")
    public Object listOfAdvancePayment(HttpServletRequest request) {
        JsonObject res = advancePaymentService.listOfAdvancePayment(request);
        return res.toString();
    }

    /*Mobile app urls end*/

    /**** Advance payment list for back office */
    @PostMapping(path = "/advancePaymentList")
    public Object advancePaymentList(@RequestBody Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject res = advancePaymentService.advancePaymentList(request, httpServletRequest);
        return  res.toString();
    }

    @PostMapping(path = "/deletePayment")
    public Object deletePayment(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        return advancePaymentService.deletePayment(jsonRequest, request);
    }

    @PostMapping(path = "/rejectAdvancePayment")
    public Object rejectAdvancePayment(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        return advancePaymentService.rejectAdvancePayment(jsonRequest, request);
    }

    @PostMapping(path = "/approveAdvancePayment")
    public Object approveAdvancePayment(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        return advancePaymentService.approveAdvancePayment(jsonRequest, request);
    }
}
