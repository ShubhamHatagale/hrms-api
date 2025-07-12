package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.LevelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class LevelController {
    @Autowired
    LevelService levelService;

    @PostMapping(path = "/createLevel")
    public ResponseEntity<?> createLevel(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return ResponseEntity.ok(levelService.createLevel(requestParam, request));
    }

    @PostMapping(path = "/findLevel")
    public Object findLevel(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return levelService.findLevel(requestParam, request);
    }

    @PostMapping(path = "/updateLevel")
    public Object updateLevel(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return levelService.updateLevel(requestParam, request);
    }

    @GetMapping(path = "/listOfLevels")
    public Object listOfLevels(HttpServletRequest httpServletRequest) {
        JsonObject res = levelService.listOfLevels(httpServletRequest);
        return res.toString();
    }

    @PostMapping(path = "/deleteLevel")
    public Object deleteLevel(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return levelService.deleteLevel(requestParam, request);
    }
}
