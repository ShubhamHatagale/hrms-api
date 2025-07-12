package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.InstallmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@RestController
public class InstallmentController {
    @Autowired
    private InstallmentService installmentService;

    @PostMapping(path = "/createInstallment")
    public Object createInstallment(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return installmentService.createInstallment(requestParam, request);
    }

    @PostMapping(path = "/getInstallmentsList")
    public Object getInstallmentsList(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject res = installmentService.getInstallmentsList(requestParam, request);
        return res.toString();
    }
    @PostMapping(path = "/listOfAdvancePaymentWithInstallments")
    public Object listOfAdvancePaymentWithInstallments(@RequestBody Map<String, String> request,HttpServletRequest httpServletRequest) {
        JsonObject res = installmentService.listOfAdvancePaymentWithInstallments(request, httpServletRequest);
        return res.toString();
    }
}
