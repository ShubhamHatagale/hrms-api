package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.common.Enums;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.master.AdvancePaymentRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeePayrollRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeRepository;
import com.opethic.hrms.HRMSNew.repositories.master.PayheadRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;
import java.text.SimpleDateFormat;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class AdvancePaymentService {
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private AdvancePaymentRepository paymentRepository;
    @Autowired
    Utility utility;
    @Autowired
    private EmployeePayrollRepository employeePayrollRepository;
    @Autowired
    private PayheadRepository payheadRepository;
    @Autowired
    private EmployeeRepository employeeRepository;

    public Object createAdvancePaymentRequest(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        AdvancePayment advancePayment = new AdvancePayment();
        try {
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            advancePayment.setEmployee(employee);
//            employee.getAdvancePaymentList().add(advancePayment);
            advancePayment.setDateOfRequest(LocalDate.parse(requestParam.get("dateOfRequest")));
            advancePayment.setRequestAmount(Integer.parseInt(requestParam.get("requestAmount")));

            if(requestParam.containsKey("isInstallment")) {
                advancePayment.setIsInstallment(Boolean.parseBoolean(requestParam.get("isInstallment")));
                advancePayment.setNoOfInstallments(Integer.parseInt(requestParam.get("noOfInstallments")));
                advancePayment.setInstallmentAmount(Double.parseDouble(requestParam.get("installmentAmount")));
            } else
                advancePayment.setIsInstallment(false);
            advancePayment.setCreatedBy(employee.getId());
            advancePayment.setPaymentStatus(Enums.PaymentStatus.PENDING);
            advancePayment.setStatus(true);
            try {
                paymentRepository.save(advancePayment);
                responseMessage.setMessage("Saved advance payment request");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to save advance payment");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to save advance payment");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public JsonObject listOfAdvancePayment(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        try {
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            List<AdvancePayment> advancePaymentList =
                    paymentRepository.findByEmployeeIdAndStatusOrderByIdDesc(employee.getId(),
                            true);
            for (AdvancePayment advancePayment : advancePaymentList) {
                JsonObject object = new JsonObject();
                object.addProperty("id", advancePayment.getId());
                String dateOfRequest = advancePayment.getDateOfRequest() == null ? "" :
                        String.valueOf(advancePayment.getDateOfRequest());
                object.addProperty("dateOfRequest", dateOfRequest);
                object.addProperty("requestAmount", advancePayment.getRequestAmount());
                object.addProperty("reason", advancePayment.getReason());
                object.addProperty("paymentStatus", advancePayment.getPaymentStatus().toString());
                object.addProperty("isInstallment", advancePayment.getIsInstallment());
                object.addProperty("installmentAmount", advancePayment.getInstallmentAmount());
                object.addProperty("noOfInstallments", advancePayment.getNoOfInstallments());
                String paidDate = advancePayment.getPaymentDate() == null ? "" :
                        String.valueOf(advancePayment.getPaymentDate());
                object.addProperty("paidDate", paidDate);
                object.addProperty("paidAmount", advancePayment.getPaidAmount());
                object.addProperty("remark", advancePayment.getRemark());
                object.addProperty("approvedBy", advancePayment.getApprovedBy());
                object.addProperty("createdAt", String.valueOf(advancePayment.getCreatedAt()));
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
    public Object updateAdvancePayment(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            Long paymentId = Long.valueOf(jsonRequest.get("paymentId"));
            Integer paidAmount = Integer.valueOf(jsonRequest.get("paidAmount"));
            String remark = jsonRequest.get("remark");
            AdvancePayment advancePayment = paymentRepository.findByIdAndStatus(paymentId, true);
            if (advancePayment != null) {
                if (!remark.isEmpty()) {
                    advancePayment.setRemark(remark);
                }
                advancePayment.setPaymentDate(LocalDate.now());
                advancePayment.setUpdatedBy(users.getId());
                advancePayment.setUpdatedAt(LocalDateTime.now());
                paymentRepository.save(advancePayment);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
        }
        return responseMessage;
    }

    public Object rejectAdvancePayment(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            Long paymentId = Long.valueOf(jsonRequest.get("paymentId"));
            String remark = jsonRequest.get("remark");
            AdvancePayment advancePayment = paymentRepository.findByIdAndStatus(paymentId, true);
            if (advancePayment != null) {
                if (!remark.isEmpty()) {
                    advancePayment.setRemark(remark);
                }
                advancePayment.setPaymentStatus(Enums.PaymentStatus.REJECTED);
                advancePayment.setApprovedBy(users.getUsername());
                advancePayment.setUpdatedBy(users.getId());
                advancePayment.setUpdatedAt(LocalDateTime.now());
                try {
                    paymentRepository.save(advancePayment);
                    responseMessage.setMessage("Request rejected successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception " + e.getMessage());
                    responseMessage.setMessage("Failed to reject request");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } else {
                responseMessage.setMessage("Payment request not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to reject request");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object approveAdvancePayment(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        EmployeePayhead employeePayhead = null;
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            Long paymentId = Long.valueOf(jsonRequest.get("paymentId"));
            Double paidAmount = Double.parseDouble(jsonRequest.get("paidAmount"));
            int noOfInstallments = Integer.parseInt(jsonRequest.get("noOfInstallments"));
            String remark = jsonRequest.get("remark");

            Double installmentAmount = 0.0;
            if(noOfInstallments != 0)
                installmentAmount = (paidAmount/noOfInstallments);

            AdvancePayment advancePayment = paymentRepository.findByIdAndStatus(paymentId, true);
            if (advancePayment != null) {
                if (!remark.isEmpty()) {
                    advancePayment.setRemark(remark);
                }
                advancePayment.setPaymentStatus(Enums.PaymentStatus.APPROVED);
                advancePayment.setPaidAmount(paidAmount);
                advancePayment.setNoOfInstallments(noOfInstallments);
                advancePayment.setInstallmentAmount(installmentAmount);
                advancePayment.setApprovedBy(users.getUsername());
                advancePayment.setPaymentDate(LocalDate.now());
                advancePayment.setUpdatedBy(users.getId());
                advancePayment.setUpdatedAt(LocalDateTime.now());
                AdvancePayment advancePayment1 = paymentRepository.save(advancePayment);
                if(advancePayment1 != null){
                    String yearMonth = null;
                    String monthValue = null;
                    String yearValue = null;
                    yearValue = String.valueOf(advancePayment1.getDateOfRequest());
                    monthValue = String.valueOf(advancePayment1.getDateOfRequest().getMonthValue());
                    yearMonth = yearValue+"-"+monthValue;
                    EmployeePayroll employeePayroll = null;
                    employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(advancePayment1.getEmployee().getId(), yearMonth);
                    if (employeePayroll != null) {
                        Double amount = employeePayroll.getAdvance() != null ? employeePayroll.getAdvance() : 0.0;
                        amount += paidAmount;
                        employeePayroll.setAdvance(amount);
                    } else {
                        employeePayroll = new EmployeePayroll();
                        employeePayroll.setEmployee(advancePayment1.getEmployee());
                        employeePayroll.setYearMonth(yearMonth);
                        employeePayroll.setAdvance(paidAmount);
                    }
                    EmployeePayroll obj = employeePayrollRepository.save(employeePayroll);
                    if(obj != null){
                        Employee employee = advancePayment1.getEmployee();
                        employeePayhead = utility.getEmployeePayheadByKey(employee.getEmployeePayheadList(), "advance");
                        if(employeePayhead == null) {
                            employeePayhead = new EmployeePayhead();
                            List<EmployeePayhead> employeePayheadList = employee.getEmployeePayheadList();
                            Payhead payhead = utility.getPayheadByKey("advance");
                            if (payhead != null) {
                                employeePayhead.setPayhead(payhead);
                            } else {
                                payhead = new Payhead();
                                payhead.setName("Advance");
                                payhead.setPayheadSlug(utility.getKeyName("Advance", false));
                                payhead.setPercentage(0.0);
                                payhead.setPercentageOf(null);
                                payhead.setCreatedBy(users.getId());
                                payhead.setCreatedAt(LocalDateTime.now());
                                payhead.setStatus(true);
                                payhead.setIsDefault(false);
                                employeePayhead.setPayhead(payheadRepository.save(payhead));
                            }
                            employeePayhead.setAmount(paidAmount);
                            employeePayhead.setIsDeduction(true);
                            employeePayheadList.add(employeePayhead);
                            employee.setEmployeePayheadList(employeePayheadList);
                            employeeRepository.save(employee);
                        }
                    }
                    responseMessage.setMessage("Request approved successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } else {
                    responseMessage.setMessage("Trouble while approving advance payment");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } else {
                responseMessage.setMessage("Payment request not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to approve request");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject advancePaymentDashboard(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        try {
            JsonObject jsonObject = new JsonObject();
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            Double empSal = employee.getExpectedSalary();
            Double creditAmt = (empSal * 0.6);
            jsonObject.addProperty("employeeSalary",empSal);
            jsonObject.addProperty("employeeCreditSalary",creditAmt);
            responseMessage.add("response", jsonObject);
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject advancePaymentList(Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<AdvancePayment> advancePaymentList = null;
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
                    advancePaymentList = paymentRepository.getPaymentRequestsBetweenDates(fromDate, toDate);
                else
                    advancePaymentList = paymentRepository.getPaymentRequestsForCurrentMonth(LocalDate.now().getMonthValue(), LocalDate.now().getYear());
                for (AdvancePayment advancePayment : advancePaymentList) {
                    JsonObject object = new JsonObject();
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
                    object.addProperty("installmentAmount", advancePayment.getIsInstallment());
                    object.addProperty("noOfInstallments", advancePayment.getNoOfInstallments());
                    String paidDate = advancePayment.getPaymentDate() == null ? "" :
                            String.valueOf(advancePayment.getPaymentDate());
                    object.addProperty("paidDate", paidDate);
                    object.addProperty("paidAmount", advancePayment.getPaidAmount());
                    object.addProperty("remark", advancePayment.getRemark());
                    object.addProperty("approvedBy", advancePayment.getApprovedBy());
                    object.addProperty("createdAt", String.valueOf(advancePayment.getCreatedAt()));
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

    public Object deletePayment(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            Long paymentId = Long.valueOf(jsonRequest.get("paymentId"));
            AdvancePayment advancePayment = paymentRepository.findByIdAndStatus(paymentId, true);
            if (advancePayment != null) {
                advancePayment.setStatus(false);
                advancePayment.setUpdatedBy(users.getId());
                advancePayment.setUpdatedAt(LocalDateTime.now());
                paymentRepository.save(advancePayment);
                responseMessage.setMessage("Advance Payment Deleted Successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseMessage.setMessage("Payment request not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to approve request");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
}
