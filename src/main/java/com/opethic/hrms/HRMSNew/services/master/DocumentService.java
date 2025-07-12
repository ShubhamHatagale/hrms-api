package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.Document;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.DocumentRepository;
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
public class DocumentService {

    @Autowired
    DocumentRepository documentRepository;
    @Autowired
    JwtTokenUtil jwtTokenUtil;
    @PersistenceContext
    private EntityManager entityManager;

    public Object createDocument(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        try {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Document document = new Document();
            document.setDocumentName(requestParam.get("documentName"));
            document.setIsRequired(Boolean.parseBoolean(requestParam.get("isRequired")));
            document.setStatus(true);
            document.setCreatedBy(user.getId());
            document.setCompany(user.getCompany());
            document.setBranch(user.getBranch());
            try {
                Document document1 = documentRepository.save(document);
                responseObject.setResponse(document1);
                responseObject.setMessage("Document saved successfully");
                responseObject.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                responseObject.setMessage("Failed to save document");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            responseObject.setMessage("Failed to save document");
        }
        return responseObject;
    }

    public JsonObject listOfDocument(HttpServletRequest httpServletRequest) {
        Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest .getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Document> documentList = null;
        try {
            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
                documentList = documentRepository.findAllByCompanyIdAndStatus(users.getCompany().getId(), true);
            } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
                documentList = documentRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
            }
            if(documentList != null) {
                for (Document document : documentList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", document.getId());
                    object.addProperty("documentName", document.getDocumentName());
                    object.addProperty("isRequired", document.getIsRequired());
                    object.addProperty("createdDate", document.getCreatedAt().toString());
                    jsonArray.add(object);
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Data not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object findDocument(Map<String, String> requestParam) {
        ResponseMessage responseMessage = new ResponseMessage();
        try {
            Document document = documentRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
            if (document != null) {
                responseMessage.setResponse(document);
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseMessage.setMessage("Data not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to load data");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object updateDocument(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Document document = documentRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
        if (document != null) {
            document.setDocumentName(requestParam.get("documentName"));
            document.setIsRequired(Boolean.parseBoolean(requestParam.get("isRequired")));
            document.setUpdatedBy(user.getId());
            document.setUpdatedAt(LocalDateTime.now());
            document.setCompany(user.getCompany());
            document.setBranch(user.getBranch());
            try {
                documentRepository.save(document);
                responseMessage.setMessage("Document updated successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                responseMessage.setMessage("Failed to update document");
            }
        } else {
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }

    public Object deleteDocument(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Document document = documentRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
        if (document != null) {
            document.setStatus(false);
            document.setUpdatedBy(user.getId());
            document.setUpdatedAt(LocalDateTime.now());
            document.setCompany(user.getCompany());
            document.setBranch(user.getBranch());
            try {
                documentRepository.save(document);
                responseMessage.setMessage("Document deleted successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                responseMessage.setMessage("Failed to delete document");
            }
        } else {
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }
}
