package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.Designation;
import com.opethic.hrms.HRMSNew.models.master.Level;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.LevelRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class LevelService {
    @Autowired
    LevelRepository levelRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;
    @PersistenceContext
    private EntityManager entityManager;

    public Object createLevel(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        Level level = new Level();
        level.setLevelName(requestParam.get("levelName"));
        level.setStatus(true);

        if (request.getHeader("Authorization") != null) {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            level.setCreatedBy(user.getId());
            level.setCompany(user.getCompany());
            level.setBranch(user.getBranch());
        }
        try {
            Level level1 = levelRepository.save(level);
            responseObject.setResponse(level1);
            responseObject.setMessage("Level added successfully");
            responseObject.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {
            responseObject.setMessage("Failed to create Level");
            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
        }
        return responseObject;
    }

    public Object findLevel(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long levelId = Long.parseLong(requestParam.get("id"));
        try {
            Level level = levelRepository.findByIdAndStatus(levelId, true);
            if (level != null) {
                responseMessage.setResponse(level);
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseMessage.setMessage("Data not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }

    public Object updateLevel(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Level level = levelRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),
                true);
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        level.setLevelName(requestParam.get("levelName"));
        level.setUpdatedBy(users.getId());
        level.setCompany(users.getCompany());
        level.setBranch(users.getBranch());
        try {
            levelRepository.save(level);
            responseMessage.setMessage("Level updated successfully");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to update");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public JsonObject listOfLevels(HttpServletRequest httpServletRequest) {
        Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest .getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        try {
            if(users.getIsAdmin()){
                List<Level> levelList = levelRepository.findAllByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(),users.getBranch().getId(),true);
                for (Level level : levelList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", level.getId());
                    object.addProperty("levelName", level.getLevelName());
                    object.addProperty("createdDate",level.getCreatedAt().toString());
                    jsonArray.add(object);
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            }else {
                response.addProperty("message", "Unauthorized user");
                response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object deleteLevel(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Level level = levelRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
        if (level != null) {
            level.setStatus(false);
            level.setUpdatedAt(LocalDateTime.now());
            try {
                levelRepository.save(level);
                responseMessage.setResponseStatus(HttpStatus.OK.value());
                responseMessage.setMessage("Level deleted successfully");
            } catch (Exception e) {
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to delete Level");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } else {
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            responseMessage.setMessage("Data not found");
        }
        return responseMessage;
    }
}
