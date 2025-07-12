package com.opethic.hrms.HRMSNew.services.master;

import com.opethic.hrms.HRMSNew.models.master.Document;
import com.opethic.hrms.HRMSNew.models.master.EmployeeDocument;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.DocumentRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeDocumentRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class EmployeeDocumentService {

    @Autowired
    EmployeeDocumentRepository employeeDocumentRepository;

    @Autowired
    DocumentRepository documentRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    public Object createEmployeeDocument(HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        EmployeeDocument employeeDocument = new EmployeeDocument();
        Document document = documentRepository.findByIdAndStatus(Long.parseLong(request.getParameter("documentId")), true);
        employeeDocument.setDocument(document);
        employeeDocument.setImagePath(request.getParameter("imagePath"));
        employeeDocument.setImageKey(request.getParameter("imagekey"));
        employeeDocument.setStatus(true);
        if (request.getHeader("Authorization") != null) {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            employeeDocument.setCreatedBy(user.getId());
        }
        try {
            employeeDocumentRepository.save(employeeDocument);
            responseObject.setMessage("Employee Document added successfully");
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
