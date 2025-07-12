package com.opethic.hrms.HRMSNew.services.master;

import com.opethic.hrms.HRMSNew.models.master.EmployeeExperienceDetails;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeExperienceRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class EmployeeExperienceService {

    @Autowired
    EmployeeExperienceRepository employeeExperienceRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    public Object createEmployeeExperience(HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        EmployeeExperienceDetails employeeExperience = new EmployeeExperienceDetails();
        employeeExperience.setCompanyName(request.getParameter("companyName"));
        employeeExperience.setFromMonthYear(request.getParameter("fromMonthYear"));
        employeeExperience.setToMonthYear(request.getParameter("toMonthYear"));
        employeeExperience.setDesignationName(request.getParameter("designationName"));
        employeeExperience.setLastDrawnSalary(request.getParameter("lastDrawnSalary"));
        employeeExperience.setReasonToResign(request.getParameter("reasonToResign"));
        employeeExperience.setStatus(true);
        if (request.getHeader("Authorization") != null) {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            employeeExperience.setCreatedBy(user.getId());
        }
        try {
            employeeExperienceRepository.save(employeeExperience);
            responseObject.setMessage("Employee Experience added successfully");
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
