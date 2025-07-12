package com.opethic.hrms.HRMSNew.services.master;

import com.opethic.hrms.HRMSNew.models.master.EmployeeFamily;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeFamilyRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;

@Service
public class EmployeeFamilyService {

    @Autowired
    EmployeeFamilyRepository employeeFamilyRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    public Object createEmployeeFamily(HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        EmployeeFamily employeeFamily = new EmployeeFamily();

        employeeFamily.setFullName(request.getParameter("fullName"));
        employeeFamily.setDob(request.getParameter("dob"));
        employeeFamily.setRelation(request.getParameter("relation"));
        employeeFamily.setEducation(request.getParameter("education"));
        employeeFamily.setStatus(true);
        if (request.getHeader("Authorization") != null) {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            employeeFamily.setCreatedBy(user.getId());
        }
        try {
            employeeFamilyRepository.save(employeeFamily);
            responseObject.setMessage("Employee Family added successfully");
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
