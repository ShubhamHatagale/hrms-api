package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.Designation;
import com.opethic.hrms.HRMSNew.models.master.Level;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.DesignationRepository;
import com.opethic.hrms.HRMSNew.repositories.master.LevelRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class DesignationService {

    @Autowired
    JwtTokenUtil jwtTokenUtil;
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private DesignationRepository designationRepository;
    @Autowired
    private LevelRepository levelRepository;

    public Object createDesignation(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        Level level = levelRepository.findByIdAndStatus(Long.parseLong(requestParam.get("levelId")), true);
        if(level != null) {
            Designation designation = new Designation();
            designation.setDesignationName(requestParam.get("designationName"));
            designation.setDesignationCode(requestParam.get("designationCode"));
            designation.setLevel(level);
            designation.setStatus(true);
            if (request.getHeader("Authorization") != null) {
                Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                designation.setCreatedBy(user.getId());
                designation.setCompany(user.getCompany());
                designation.setBranch(user.getBranch());
            }
            try {
                Designation designation1 = designationRepository.save(designation);
                responseObject.setResponse(designation1);
                responseObject.setMessage("Designation added successfully");
                responseObject.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                responseObject.setMessage("Failed to create designation");
                responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                e.printStackTrace();
                System.out.println("Exception:" + e.getMessage());
            }
        } else {
            responseObject.setMessage("Level not found");
            responseObject.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseObject;
    }

    public JsonObject findDesignation(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        Long designationId = Long.parseLong(requestParam.get("id"));
        try {
            Designation designation = designationRepository.findByIdAndStatus(designationId, true);
            if (designation != null) {
                JsonObject object = new JsonObject();
                object.addProperty("id", designation.getId());
                object.addProperty("designationName", designation.getDesignationName());
                object.addProperty("designationCode", designation.getDesignationCode());
                object.addProperty("levelId", designation.getLevel().getId());
                object.addProperty("levelName", designation.getLevel().getLevelName());
                responseMessage.add("response",object);
                responseMessage.addProperty("responseStatus",HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("message","Data not found");
                responseMessage.addProperty("responseStatus",HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message","Something went wrong");
            responseMessage.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object updateDesignation(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Designation designation = designationRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),
                true);
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        designation.setDesignationName(requestParam.get("designationName"));
        designation.setDesignationCode(requestParam.get("designationCode"));
        Level level = levelRepository.findByIdAndStatus(Long.parseLong(requestParam.get("levelId")), true);
        designation.setLevel(level);
        designation.setUpdatedBy(users.getId());
        designation.setCompany(users.getCompany());
        designation.setBranch(users.getBranch());
        try {
            designationRepository.save(designation);
            responseMessage.setMessage("Designation updated successfully");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to update");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public JsonObject listOfDesignation(HttpServletRequest httpServletRequest) {
        Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest .getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Designation> designationList = null;
        try {
            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
                designationList = designationRepository.findAllByCompanyIdAndStatus(users.getCompany().getId(), true);
            } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
                designationList = designationRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
            }
            if(designationList != null) {
                for (Designation designation : designationList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", designation.getId());
                    object.addProperty("designationName", designation.getDesignationName());
                    object.addProperty("designationCode", designation.getDesignationCode());
                    Level level = levelRepository.findByIdAndStatus(designation.getLevel().getId(), true);
                    object.addProperty("designationLevel", level.getLevelName());
                    object.addProperty("createdDate", designation.getCreatedAt().toString());
                    jsonArray.add(object);
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Data not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object deleteDesignation(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Designation designation = designationRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
        if (designation != null) {
            designation.setStatus(false);
            designation.setUpdatedAt(LocalDateTime.now());
            try {
                designationRepository.save(designation);
                responseMessage.setResponseStatus(HttpStatus.OK.value());
                responseMessage.setMessage("Designation deleted successfully");
            } catch (Exception e) {
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to delete designation");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } else {
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            responseMessage.setMessage("Data not found");
        }
        return responseMessage;
    }
}
