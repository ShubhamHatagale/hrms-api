package com.opethic.hrms.HRMSNew.controllers.master;

import com.opethic.hrms.HRMSNew.services.master.EmployeeExperienceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class EmployeeExperienceController {
    @Autowired
    EmployeeExperienceService employeeExperienceService;

    @PostMapping(path = "/create_emp_experience")
    public ResponseEntity<?> createEmployeeExperience(HttpServletRequest request) {
        return ResponseEntity.ok(employeeExperienceService.createEmployeeExperience(request));
    }
}
