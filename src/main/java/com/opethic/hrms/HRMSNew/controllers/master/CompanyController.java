package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.services.master.CompanyService;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class CompanyController {
    @Autowired
    private CompanyService companyService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @PostMapping(path = "/createCompany")
    public Object createCompany(MultipartHttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        if(users == null){
            JsonObject response = new JsonObject();
            response.addProperty("message", "User not authorized");
            response.addProperty("status", HttpStatus.UNAUTHORIZED.value());
            return response;
        }
        return companyService.createCompany(request, users).toString();
    }

    @PostMapping(path = "/findCompany")
    public Object findCompany(@RequestBody Map<String, String> jsonRequest) {
        return companyService.findCompany(jsonRequest).toString();
    }

    @GetMapping(path = "/listOfCompany")
    public Object listOfCompany(HttpServletRequest httpServletRequest) {
        JsonObject res = companyService.listOfCompany(httpServletRequest);
        return res.toString();
    }

    @PostMapping(path = "/deleteCompany")
    public Object deleteCompany(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        return companyService.deleteCompany(jsonRequest, request);
    }

    @PostMapping(path = "/updateCompany")
    public Object updateCompany(MultipartHttpServletRequest request) {
        return companyService.updateCompany(request).toString();
    }

    /* Get GstTypemaster */
    @GetMapping(path = "/get_gst_type")
    public Object getGstType() {
        JsonObject res = companyService.getGstType();
        return res.toString();
    }
}
