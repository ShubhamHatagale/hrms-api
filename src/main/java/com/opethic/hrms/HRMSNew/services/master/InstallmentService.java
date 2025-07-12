package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.common.Enums;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.master.AdvancePaymentRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeePayrollRepository;
import com.opethic.hrms.HRMSNew.repositories.master.InstallmentRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@Service
public class InstallmentService {
    @Autowired
    private InstallmentRepository installmentRepository;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private AdvancePaymentRepository advancePaymentRepository;
    @Autowired
    private EmployeePayrollRepository employeePayrollRepository;

    public Object createInstallment(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Installment installment = new Installment();
        try {
            AdvancePayment advancePayment = advancePaymentRepository.findByIdAndStatus(Long.parseLong(requestParam.get("advance_payment_id")), true);
            Double paidAmount = installmentRepository.getSumOfPaidAmount(advancePayment.getId());
            if(paidAmount == null || paidAmount < advancePayment.getPaidAmount()) {
                installment.setAdvancePayment(advancePayment);
                installment.setAmount(Double.parseDouble(requestParam.get("amount")));
                installment.setDueDate(LocalDate.parse(requestParam.get("approvedDate")));
                installment.setStatus(Enums.InstallmentStatus.PAID);
                Installment object = installmentRepository.save(installment);
                if (object != null) {
                    String yearMonth = null;
                    String monthValue = null;
                    String yearValue = null;
                    yearValue = String.valueOf(advancePayment.getDateOfRequest());
                    monthValue = String.valueOf(advancePayment.getDateOfRequest().getMonthValue());
                    yearMonth = yearValue+"-"+monthValue;
                    EmployeePayroll employeePayroll = null;
                    employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(advancePayment.getEmployee().getId(), yearMonth);
                    if (employeePayroll != null) {
                        Double advAmount = employeePayroll.getAdvance();
                        advAmount -= object.getAmount();
                        employeePayroll.setAdvance(advAmount);
                    }
                    EmployeePayroll obj = employeePayrollRepository.save(employeePayroll);
                    if(obj != null) {
                        responseMessage.setMessage("Installment Saved");
                        responseMessage.setResponseStatus(HttpStatus.OK.value());
                    } else {
                        responseMessage.setMessage("Trouble While updating advance in employee payroll");
                        responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                }
            } else {
                responseMessage.setMessage("Your payment is completed");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            }
        } catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to save installment");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return  responseMessage;
    }

    public JsonObject getInstallmentsList(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        try {
//            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            AdvancePayment advancePayment = advancePaymentRepository.findByIdAndStatus(Long.parseLong(requestParam.get("advance_payment_id")), true);
            List<Installment> installmentList = installmentRepository.findByAdvancePaymentId(advancePayment.getId());
            for (Installment installment : installmentList) {
                JsonObject object = new JsonObject();
                object.addProperty("id", installment.getId());
                String dueDate = installment.getDueDate() == null ? "" : String.valueOf(installment.getDueDate());
                object.addProperty("due_date", dueDate);
                object.addProperty("amount", installment.getAmount());
                object.addProperty("status", installment.getStatus().toString());
                jsonArray.add(object);
            }
            responseMessage.add("response", jsonArray);
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject listOfAdvancePaymentWithInstallments(Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<AdvancePayment> advPaymentWithInstallments = null;
        String fromDate = null;
        String toDate = null;
        if (!request.get("fromDate").equalsIgnoreCase("")) {
            fromDate = request.get("fromDate");
        }
        if (!request.get("toDate").equalsIgnoreCase("")) {
            toDate = request.get("toDate");
        }
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
            if(users.getIsSuperAdmin() || users.getIsAdmin()) {
                if(fromDate != null && toDate != null)
                    advPaymentWithInstallments = advancePaymentRepository.getPaymentRequestsWithInstallmentsBetweenDates(fromDate, toDate);
                else {
                    String month = LocalDate.now().getMonthValue() < 10 ? "0"+LocalDate.now().getMonthValue() : String.valueOf(LocalDate.now().getMonthValue());
                    String year = String.valueOf(LocalDate.now().getYear());
                    advPaymentWithInstallments = advancePaymentRepository.getPaymentRequestsWithInstallmentsForCurrentMonth(month, year);
                }
                for (AdvancePayment advancePayment : advPaymentWithInstallments) {
                    JsonObject object = new JsonObject();
                    JsonArray installmentArray = new JsonArray();
                    object.addProperty("id", advancePayment.getId());
                    String dateOfRequest = advancePayment.getDateOfRequest() == null ? "" :
                            String.valueOf(advancePayment.getDateOfRequest());
                    object.addProperty("employeeName",advancePayment.getEmployee().getFullName());
                    object.addProperty("dateOfRequest", dateOfRequest);
                    if(advancePayment.getApprovedBy()!=null){
                        object.addProperty("approvedBy",advancePayment.getApprovedBy());
                    }
                    if(advancePayment.getPaidAmount()!=null){
                        object.addProperty("paidAmount",advancePayment.getPaidAmount());
                    }
                    object.addProperty("requestAmount", advancePayment.getRequestAmount());
                    object.addProperty("reason", advancePayment.getReason());
                    object.addProperty("paymentStatus", advancePayment.getPaymentStatus().toString());
                    object.addProperty("isInstallment", advancePayment.getIsInstallment());
                    object.addProperty("installmentAmount", advancePayment.getInstallmentAmount());
                    object.addProperty("noOfInstallments", advancePayment.getNoOfInstallments());
                    String paidDate = advancePayment.getPaymentDate() == null ? "" :
                            String.valueOf(advancePayment.getPaymentDate());
                    object.addProperty("remark", advancePayment.getRemark());
                    object.addProperty("approvedBy", advancePayment.getApprovedBy());
                    object.addProperty("createdAt", String.valueOf(advancePayment.getCreatedAt()));
                    Double paidAmount = installmentRepository.getSumOfPaidAmount(advancePayment.getId());
                    if(paidAmount != null || paidAmount == advancePayment.getPaidAmount()) {
                        object.addProperty("isPaymentCompleted","Completed");
                    }
                    List<Installment> installmentList = installmentRepository.findByAdvancePaymentId(advancePayment.getId());
                    if(installmentList != null) {
                        for (Installment installment : installmentList) {
                            JsonObject installmentObject = new JsonObject();
                            installmentObject.addProperty("id", installment.getId());
                            String dueDate = installment.getDueDate() == null ? "" : String.valueOf(installment.getDueDate());
                            installmentObject.addProperty("due_date", dueDate);
                            installmentObject.addProperty("amount", installment.getAmount());
                            installmentObject.addProperty("status", installment.getStatus().toString());
                            installmentArray.add(installmentObject);
                        }
                        object.add("installmentData", installmentArray);
                    }
                    jsonArray.add(object);
                }
                responseMessage.add("response", jsonArray);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("response", "You are not admin");
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
}
