package com.opethic.hrms.HRMSNew.services.master;

import com.opethic.hrms.HRMSNew.models.master.EmployeeReference;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeReferenceRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class EmployeeReferenceService {
    @Autowired
    EmployeeReferenceRepository employeeReferenceRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    public Object createEmployeeReference(HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        EmployeeReference employeeReference = new EmployeeReference();
        employeeReference.setName(request.getParameter("name"));
        employeeReference.setAddress(request.getParameter("address"));
        employeeReference.setBusiness(request.getParameter("business"));
        employeeReference.setMobileNumber(String.valueOf(request.getParameter("mobileNumber")));
//        employeeReference.setKnownFromWhen(request.getParameter("knownFromWhen"));
        employeeReference.setStatus(true);
        if (request.getHeader("Authorization") != null) {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            employeeReference.setCreatedBy(user.getId());
        }
        try {
            employeeReferenceRepository.save(employeeReference);
            responseObject.setMessage("Employee Reference added successfully");
            responseObject.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {

            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            responseObject.setMessage("Internal Server Error");
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
        }
        return responseObject;
    }
}
