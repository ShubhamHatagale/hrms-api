package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.DepartmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class DepartmentController {

    @Autowired
    private DepartmentService departmentService;

    @PostMapping(path="/createDepartment")
    public Object createDepartment(@RequestBody Map<String,String> requestParam, HttpServletRequest request){
        return departmentService.createDepartment(requestParam,request);
    }

    @GetMapping(path = "/listOfDepartment")
    public Object listOfDepartment(HttpServletRequest httpServletRequest){
        JsonObject res=departmentService.listOfDepartment(httpServletRequest);
        return res.toString();
    }

    @PostMapping(path = "/findDepartment")
    public Object findDepartment(@RequestBody Map<String,String> requestParam,HttpServletRequest request){
        return departmentService.findDepartment(requestParam,request);
    }

    @PostMapping(path = "/updateDepartment")
    public Object updateDepartment(@RequestBody Map<String,String> requestParam,HttpServletRequest request){
        return departmentService.updateDepartment(requestParam,request);
    }

    @PostMapping(path = "/deleteDepartment")
    public Object deleteDepartment(@RequestBody Map<String,String> requestParam,HttpServletRequest request){
        return departmentService.deleteDepartment(requestParam,request);
    }
}
