package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.BranchService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class BranchController {
    @Autowired
    private BranchService branchService;

    @PostMapping(path = "/createBranch")
    public ResponseEntity<?> createBranch(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return ResponseEntity.ok(branchService.createBranch(requestParam, request));
    }

    @PostMapping(path = "/findBranch")
    public Object findBranch(@RequestBody Map<String, String> requestParam) {
        return branchService.findBranch(requestParam).toString();
    }

    @PostMapping(path = "/updateBranch")
    public Object updateBranch(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return branchService.updateBranch(requestParam, request);
    }

    @GetMapping(path = "/listOfBranch")
    public Object listOfBranch(HttpServletRequest request) {
        JsonObject object = branchService.listOfBranch(request);
        return object.toString();
    }

    @PostMapping(path = "/deleteBranch")
    public Object deleteBranch(@RequestBody Map<String,String> requestParam,HttpServletRequest request){
        return branchService.deleteBranch(requestParam,request);
    }
}
