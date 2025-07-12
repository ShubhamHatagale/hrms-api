package com.opethic.hrms.HRMSNew.services.master;

import com.opethic.hrms.HRMSNew.models.master.EmployeeEducation;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeEducationRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class EmployeeEducationService {
    @Autowired
    EmployeeEducationRepository employeeEducationRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    public Object createEmployeeEducation(HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        EmployeeEducation employeeEducation = new EmployeeEducation();
        employeeEducation.setInstitutionName(request.getParameter("institutionName"));
        employeeEducation.setQualification(request.getParameter("qualification"));
        employeeEducation.setUniversity(request.getParameter("university"));
        employeeEducation.setYear(request.getParameter("year"));
        employeeEducation.setGrade(request.getParameter("grade"));
        employeeEducation.setPercentage(request.getParameter("percentage"));
        employeeEducation.setStatus(true);
        if (request.getHeader("Authorization") != null) {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            employeeEducation.setCreatedBy(user.getId());
        }
        try {
            employeeEducationRepository.save(employeeEducation);
            responseObject.setMessage("Employee Education added successfully");
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
