package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.common.LedgerCommonPostings;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionPostingsRepository;
import com.opethic.hrms.HRMSNew.repositories.master.*;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.payment_repository.TranxPaymentPerticularsRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.apache.commons.math3.util.Precision;
import org.apache.logging.log4j.LogManager;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service
public class PayrollService {
    private static final Logger payrollLogger = LoggerFactory.getLogger(PayrollService.class);

    static String[] empSalaryHEADERs = {"Employee Name", "Company", "Days", "WH(HR)","Days Wages", "Hour Wages", "Point Wages", "Pcs Wages","Net Salary", "BASIC(AMT/%)", "Sp. Allowance",
            "P/F(AMT/%)", "ESI(AMT/%)", "Total Ded.", "Payable", "Advance", "Incentive", "Net Payable"};
    static String empSalarySHEET = "Emp_Salary_Sheet";
    private static final org.apache.logging.log4j.Logger ledgerLogger = LogManager.getLogger(PayrollService.class);
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private AttendanceRepository attendanceRepository;
    @Autowired
    private AttendanceService attendanceService;
    @Autowired
    private EmployeeLeaveRepository employeeLeaveRepository;
//    @Autowired
//    private PayheadRepository payheadRepository;
//    @Autowired
//    private MasterPayheadRepository masterPayheadRepository;
    @Autowired
    private EmployeePayrollRepository employeePayrollRepository;
    @Autowired
    private EmployeeRepository employeeRepository;
    @Autowired
    private EntityManager entityManager;
//    @Autowired
//    private AllowanceRepository allowanceRepository;
//    @Autowired
//    private DeductionRepository deductionRepository;
//    @Autowired
//    private AdvancePaymentRepository advancePaymentRepository;
    @Autowired
    private Utility utility;
    @Autowired
    private LedgerCommonPostings ledgerCommonPostings;
    @Autowired
    private TranxEmpPayrollRepository tranxEmpPayrollRepository;

    @Autowired
    private GenerateFiscalYear generateFiscalYear;
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    private TransactionTypeMasterRepository transactionTypeMasterRepository;
    @Autowired
    private TranxPaymentPerticularsRepository tranxPaymentPerticularsRepository;
    @Autowired
    private LedgerTransactionPostingsRepository ledgerTransactionPostingsRepository;

    public JsonObject getCurrentMonthPayslip(Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();

        try {
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            System.out.println("employee.getId() " + employee.getId());

            String yearMonth = null;
            if (!jsonRequest.get("currentMonth").equals("")) {
                System.out.println("jsonRequest " + jsonRequest.get("currentMonth"));
                String[] currentMonth = jsonRequest.get("currentMonth").split("-");
                String userMonth = currentMonth[0];
                String userYear = currentMonth[1];
//                String monthValue = Integer.parseInt(userMonth) < 10 ? "0"+userMonth : userMonth;
                yearMonth = userYear + "-" + userMonth;
            } else {
                String monthValue = LocalDate.now().getMonthValue() < 10 ? "0"+LocalDate.now().getMonthValue() : String.valueOf(LocalDate.now().getMonthValue());
                yearMonth = LocalDate.now().getYear() + "-" + monthValue;
            }
            System.out.println("yearMonth " + yearMonth);
            EmployeePayroll employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(employee.getId(),
                    yearMonth);
            if (employeePayroll != null) {
                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("employeeId", employeePayroll.getEmployee().getId());
                jsonObject.addProperty("employeeName", utility.getEmployeeName(employeePayroll.getEmployee()));
                jsonObject.addProperty("netSalary", employeePayroll.getNetSalary());
                jsonObject.addProperty("pfPercentage", employeePayroll.getPfPer());
                jsonObject.addProperty("pfAmount", employeePayroll.getPf());
                jsonObject.addProperty("esiPercentage", employeePayroll.getEsiPer());
                jsonObject.addProperty("esiAmount", employeePayroll.getEsi());
                jsonObject.addProperty("profTax", employeePayroll.getPfTax());
                jsonObject.addProperty("totalDeduction", employeePayroll.getTotalDeduction());
                jsonObject.addProperty("payableAmount", employeePayroll.getPayableAmount());
                jsonObject.addProperty("advance", employeePayroll.getAdvance());
                jsonObject.addProperty("overtime", employeePayroll.getOvertimeAmount());
                jsonObject.addProperty("incentive", employeePayroll.getIncentive());
                jsonObject.addProperty("netPayableAmount", employeePayroll.getNetPayableAmount());
                jsonObject.addProperty("totalHoursInMonth", employeePayroll.getTotalHoursInMonth());
                jsonObject.addProperty("employeeHavePf", employeePayroll.getEmployee().getEmployeeHavePf());
                jsonObject.addProperty("employeeHaveEsi", employeePayroll.getEmployee().getEmployeeHaveEsi());
                jsonObject.addProperty("totalAmount",employeePayroll.getMonthlyPay());
                jsonObject.addProperty("basic",employeePayroll.getBasic());
                jsonObject.addProperty("grossTotal",employeePayroll.getGrossTotal());
                jsonObject.addProperty("specialAllowance",employeePayroll.getSpecialAllowance());

                if (employee.getWagesOptions() != null) {
                    String[] wagesArr = employee.getWagesOptions().split(",");
                    if (wagesArr.length > 0) {
                        if (Arrays.asList(wagesArr).contains("hour")) {
                            jsonObject.addProperty("netSalaryInHours", employeePayroll.getNetSalaryInHours());
                        }
                        if (Arrays.asList(wagesArr).contains("day")) {
                            jsonObject.addProperty("netSalaryInDays", employeePayroll.getNetSalaryInDays());
                        }
                    }
                }

                responseMessage.add("response", jsonObject);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("response", "NA");
                responseMessage.addProperty("message", "Data not found.");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            payrollLogger.error("getCurrentMonthPayslip Exception ===>" + e);
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.addProperty("message", "Failed to load data.");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        return responseMessage;
    }


    public JsonObject getEmpSalaryslip(Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();

        try {
            Employee employee = employeeRepository.findByIdAndStatus(Long.parseLong(jsonRequest.get("employeeId")), true);
            System.out.println("employee.getId() " + employee.getId());

            String yearMonth = null;
            if (!jsonRequest.get("fromMonth").equals("")) {
                System.out.println("jsonRequest " + jsonRequest.get("fromMonth"));
                String[] fromMonth = jsonRequest.get("fromMonth").split("-");
                int userMonth = Integer.parseInt(fromMonth[1]);
                int userYear = Integer.parseInt(fromMonth[0]);
                yearMonth = userYear + "-" + userMonth;
            } else {
                yearMonth = LocalDate.now().getYear() + "-" + LocalDate.now().getMonthValue();
            }
            System.out.println("yearMonth" + yearMonth);
            EmployeePayroll employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(employee.getId(),
                    yearMonth);
            if (employeePayroll != null) {
                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("employeeId", employeePayroll.getEmployee().getId());
                jsonObject.addProperty("employeeName", utility.getEmployeeName(employeePayroll.getEmployee()));
                jsonObject.addProperty("designation", employeePayroll.getEmployee().getDesignation().getDesignationName());
                jsonObject.addProperty("mobileNo", employeePayroll.getEmployee().getMobileNumber());
                jsonObject.addProperty("address", employeePayroll.getEmployee().getPermanentAddress());
                jsonObject.addProperty("netSalary", Precision.round(employeePayroll.getNetSalary(), 2));
                jsonObject.addProperty("pfPercentage", Precision.round(employeePayroll.getPfPer(), 2));
                jsonObject.addProperty("pfAmount", Precision.round(employeePayroll.getPf(), 2));
                jsonObject.addProperty("esiPercentage", Precision.round(employeePayroll.getEsiPer(), 2));
                jsonObject.addProperty("esiAmount", Precision.round(employeePayroll.getEsi(), 2));
                jsonObject.addProperty("profTax", Precision.round(employeePayroll.getPfTax(), 2));
                jsonObject.addProperty("totalDeduction", Precision.round(employeePayroll.getTotalDeduction(), 2));
                jsonObject.addProperty("payableAmount", Precision.round(employeePayroll.getPayableAmount(), 2));
                jsonObject.addProperty("advance", Precision.round(employeePayroll.getAdvance(), 2));
                jsonObject.addProperty("incentive", Precision.round(employeePayroll.getIncentive(), 2));
                jsonObject.addProperty("netPayableAmount", Precision.round(employeePayroll.getNetPayableAmount(), 2));
                jsonObject.addProperty("noDaysPresent", Precision.round(employeePayroll.getNoDaysPresent(), 2));
                jsonObject.addProperty("totalHoursInMonth", Precision.round(employeePayroll.getTotalHoursInMonth(), 2));


                if (employee.getWagesOptions() != null) {
                    String[] wagesArr = employee.getWagesOptions().split(",");
                    if (wagesArr.length > 0) {

                        jsonObject.addProperty("netSalaryInHours", Precision.round(employeePayroll.getNetSalaryInHours(), 2));
                        jsonObject.addProperty("netSalaryInDays", Precision.round(employeePayroll.getNetSalaryInDays(), 2));
                    }
                }

                responseMessage.add("response", jsonObject);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("response", "NA");
                responseMessage.addProperty("message", "Data not found.");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            payrollLogger.error("getCurrentMonthPayslip Exception ===>" + e);
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.addProperty("message", "Failed to load data.");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        return responseMessage;
    }

    public InputStream getExcelEmployeePaymentSheet(String yearMonth, String companyId, HttpServletRequest request) {

        try {
            System.out.println("yearMonth " + yearMonth);

            int year = Integer.parseInt(yearMonth.split("-")[0]);
            int month = Integer.parseInt(yearMonth.split("-")[1]);
            yearMonth = year + "-" + month;
            System.out.println("yearMonth " + yearMonth);

            JsonArray employeeArray = new JsonArray();
            List<Employee> employees = new ArrayList<>();

            if (companyId.equalsIgnoreCase("all"))
                employees = employeeRepository.findByStatus(true);
            else
                employees = employeeRepository.findByCompanyIdAndStatus(Long.valueOf(companyId), true);
            for (Employee employee : employees) {
                JsonObject empObject = new JsonObject();
                empObject.addProperty("id", employee.getId());
                empObject.addProperty("employeeName", utility.getEmployeeName(employee));
                empObject.addProperty("companyName", employee.getCompany().getCompanyName());

                EmployeePayroll employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(employee.getId(), yearMonth);
                if (employeePayroll != null) {
                    empObject.addProperty("days", employeePayroll.getNoDaysPresent());
                    empObject.addProperty("workingHour", Precision.round(employeePayroll.getTotalHoursInMonth(), 2));
                    empObject.addProperty("netSalaryInHours", Precision.round(employeePayroll.getNetSalaryInHours(), 2));
//                    empObject.addProperty("netSalaryInPoints", Precision.round(employeePayroll.getNetSalaryInPoints(), 2));
                    empObject.addProperty("netSalaryInDays", Precision.round(employeePayroll.getNetSalaryInDays(), 2));
//                    empObject.addProperty("netSalaryInPcs", Precision.round(employeePayroll.getNetSalaryInPcs(), 2));
                    empObject.addProperty("netSalary", Precision.round(employeePayroll.getNetSalary(), 2));
                    empObject.addProperty("basicPer", Precision.round(employeePayroll.getBasicPer(), 2));
                    empObject.addProperty("basic", Precision.round(employeePayroll.getBasic(), 2));
                    empObject.addProperty("specialAllowance", Precision.round(employeePayroll.getSpecialAllowance(), 2));
                    empObject.addProperty("pfPer", Precision.round(employeePayroll.getPfPer(), 2));
                    empObject.addProperty("pf", Precision.round(employeePayroll.getPf(), 2));
                    empObject.addProperty("esiPer", Precision.round(employeePayroll.getEsiPer(), 2));
                    empObject.addProperty("esi", Precision.round(employeePayroll.getEsi(), 2));
                    empObject.addProperty("totalDeduction", Precision.round(employeePayroll.getTotalDeduction(), 2));
                    empObject.addProperty("payableAmount", Precision.round(employeePayroll.getPayableAmount(), 2));
                    empObject.addProperty("advance", Precision.round(employeePayroll.getAdvance(), 2));
                    empObject.addProperty("incentive", Precision.round(employeePayroll.getIncentive(), 2));
                    empObject.addProperty("netPayableAmount", Precision.round(employeePayroll.getNetPayableAmount(), 2));

                    employeeArray.add(empObject);
                }
            }

            ByteArrayInputStream in = convertToExcel(employeeArray);

            return in;
        } catch (Exception e) {
            payrollLogger.error("Failed to load data " + e);
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            throw new RuntimeException("fail to import data to Excel file: " + e.getMessage());
        }
    }

    private ByteArrayInputStream convertToExcel(JsonArray jsonArray) {
        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet(empSalarySHEET);

            // Header
            Row headerRow = sheet.createRow(0);

            // Define header cell style
            CellStyle headerCellStyle = workbook.createCellStyle();
            headerCellStyle.setFillForegroundColor(IndexedColors.LIGHT_GREEN.getIndex());
            headerCellStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

            for (int col = 0; col < empSalaryHEADERs.length; col++) {
                Cell cell = headerRow.createCell(col);
                cell.setCellValue(empSalaryHEADERs[col]);
                cell.setCellStyle(headerCellStyle);
            }

            int rowIdx = 1;
            for (JsonElement jsonElement : jsonArray) {
                JsonObject obj = jsonElement.getAsJsonObject();
                Row row = sheet.createRow(rowIdx++);
                try {
                    row.createCell(0).setCellValue(obj.get("employeeName").getAsString());
                    row.createCell(1).setCellValue(obj.get("companyName").getAsString());

                    row.createCell(2).setCellValue(obj.get("days").getAsString());
                    row.createCell(3).setCellValue(obj.get("workingHour").getAsString());
                    row.createCell(4).setCellValue(obj.get("netSalaryInDays").getAsString());
                    row.createCell(5).setCellValue(obj.get("netSalaryInHours").getAsString());
                    row.createCell(6).setCellValue(obj.get("netSalaryInPoints").getAsString());
                    row.createCell(7).setCellValue(obj.get("netSalaryInPcs").getAsString());
                    row.createCell(8).setCellValue(obj.get("netSalary").getAsString());
//                    row.createCell(5).setCellValue(obj.get("basic").getAsString() + " (" + obj.get("basicPer").getAsString() + ")");
                    row.createCell(9).setCellValue(obj.get("basic").getAsString());
                    row.createCell(10).setCellValue(obj.get("specialAllowance").getAsString());
//                    row.createCell(7).setCellValue(obj.get("pf").getAsString() + " (" + obj.get("pfPer").getAsString() + ")");
                    row.createCell(11).setCellValue(obj.get("pf").getAsString());
//                    row.createCell(8).setCellValue(obj.get("esi").getAsString() + " (" + obj.get("esiPer").getAsString() + ")");
                    row.createCell(12).setCellValue(obj.get("esi").getAsString());
                    row.createCell(13).setCellValue(obj.get("totalDeduction").getAsString());
                    row.createCell(14).setCellValue(obj.get("payableAmount").getAsString());
                    row.createCell(15).setCellValue(obj.get("advance").getAsString());
                    row.createCell(16).setCellValue(obj.get("incentive").getAsString());
                    row.createCell(17).setCellValue(obj.get("netPayableAmount").getAsString());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception e");
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            workbook.write(out);

            byte[] b = new ByteArrayInputStream(out.toByteArray()).readAllBytes();
            if (b.length > 0) {
                String s = new String(b);
                System.out.println("data ------> " + s);
            } else {
                System.out.println("Empty");
            }
            return new ByteArrayInputStream(out.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("fail to import data to Excel file: " + e.getMessage());
        }
    }

    public JsonObject getEmployeeIdByLedgerId(HttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject result = new JsonObject();
        Long ledgerId = Long.parseLong(request.getParameter("ledger_id"));
        LedgerMaster ledgerMaster = ledgerMasterRepository.findByIdAndCompanyIdAndStatus(ledgerId, users.getCompany().getId(),  true);
        JsonObject ledgerData = new JsonObject();
        if(ledgerMaster != null){
            result.addProperty("employee_id",ledgerMaster.getEmployee().getId());
            result.addProperty("message", "success");
            result.addProperty("responseStatus", HttpStatus.OK.value());
        } else {
            result.addProperty("message", "Not Found");
            result.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
        }
        return result;
    }

    public JsonObject getEmpSalaryWithLedgers(Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Long empId = Long.parseLong(jsonRequest.get("employeeId"));
        Double closingBalance = 0.0;
        Double sumCR = 0.0;
        Double sumDR = 0.0;
        DecimalFormat df = new DecimalFormat("0.00");
        LedgerMaster mLedger = ledgerMasterRepository.findByEmployeeIdAndStatus(empId, true);
//        LedgerMaster ledgerMaster = ledgerMasterRepository.findByEmployeeIdAndStatus(empId, true);
        try {
            Employee employee = employeeRepository.findByIdAndStatus(empId, true);
            if(employee != null){
                String yearMonth = null;
                String monthValue = null;
                String yearValue = null;
                if (!jsonRequest.get("fromMonth").equals("")) {
                    String[] fromMonth = jsonRequest.get("fromMonth").split("-");
                    int userMonth = Integer.parseInt(fromMonth[1]);
                    int userYear = Integer.parseInt(fromMonth[0]);
                    monthValue = userMonth < 10 ? "0"+userMonth : String.valueOf(userMonth);
                    yearValue = String.valueOf(userYear);
                    yearMonth = yearValue+"-"+monthValue;
                } else {
                    yearValue = String.valueOf(LocalDate.now().getYear());
                    monthValue = String.valueOf(LocalDate.now().getMonthValue());
                    yearMonth = yearValue+"-"+monthValue;
                }
                System.out.println("yearMonth" + yearMonth);
                EmployeePayroll employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(employee.getId(), yearMonth);
                if (employeePayroll != null) {
                    JsonObject jsonObject = new JsonObject();
                    jsonObject.addProperty("employeeId", employeePayroll.getEmployee().getId());
                    jsonObject.addProperty("employeeName", utility.getEmployeeName(employeePayroll.getEmployee()));
                    jsonObject.addProperty("designation", employeePayroll.getEmployee().getDesignation().getDesignationName());
                    jsonObject.addProperty("mobileNo", employeePayroll.getEmployee().getMobileNumber());
                    jsonObject.addProperty("address", employeePayroll.getEmployee().getPermanentAddress());
                    jsonObject.addProperty("basic", Precision.round(employeePayroll.getBasic(), 2));
                    jsonObject.addProperty("specialAllowance", Precision.round(employeePayroll.getSpecialAllowance(),2));
                    jsonObject.addProperty("netSalary", Precision.round(employeePayroll.getNetSalary(), 2));
                    jsonObject.addProperty("pfPercentage", Precision.round(employeePayroll.getPfPer(), 2));
                    jsonObject.addProperty("pfAmount", Precision.round(employeePayroll.getPf(), 2));
                    jsonObject.addProperty("esiPercentage", Precision.round(employeePayroll.getEsiPer(), 2));
                    jsonObject.addProperty("esiAmount", Precision.round(employeePayroll.getEsi(), 2));
                    jsonObject.addProperty("profTax", Precision.round(employeePayroll.getPfTax(), 2));
                    jsonObject.addProperty("totalDeduction", Precision.round(employeePayroll.getTotalDeduction(), 2));
                    jsonObject.addProperty("payableAmount", Precision.round(employeePayroll.getPayableAmount(), 2));
                    jsonObject.addProperty("advance", employeePayroll.getAdvance() != null ? Precision.round(employeePayroll.getAdvance(), 2): 0.0);
                    jsonObject.addProperty("incentive", Precision.round(employeePayroll.getIncentive(), 2));
                    jsonObject.addProperty("netPayableAmount", Precision.round(employeePayroll.getNetPayableAmount(), 2));
                    jsonObject.addProperty("noDaysPresent", Precision.round(employeePayroll.getNoDaysPresent(), 2));
                    jsonObject.addProperty("totalHoursInMonth", Precision.round(employeePayroll.getTotalHoursInMonth(), 2));
                    jsonObject.addProperty("totalDays",employeePayroll.getTotalDays());
                    jsonObject.addProperty("perDaySalary",employeePayroll.getPerDaySalary());
                    jsonObject.addProperty("neySalary",employeePayroll.getNetSalary());
                    jsonObject.addProperty("monthlyPay",employeePayroll.getMonthlyPay());
                    jsonObject.addProperty("totalDaysInMonth",employeePayroll.getDaysInMonth());
                    jsonObject.addProperty("grossTotal",employeePayroll.getGrossTotal());
                    jsonObject.addProperty("leaveDays",employeePayroll.getLeaveDays());
                    jsonObject.addProperty("presentDays",employeePayroll.getPresentDays());
                    jsonObject.addProperty("totalDaysOfEmployee",Precision.round(employeePayroll.getTotalDaysOfEmployee(),2));
                    jsonObject.addProperty("extraDays",employeePayroll.getExtraDays());
                    jsonObject.addProperty("extraDaysSalary",employeePayroll.getExtraDaysSalary());
                    jsonObject.addProperty("extraHalfDays",employeePayroll.getExtraHalfDays());
                    jsonObject.addProperty("extraHalfDaysSalary",employeePayroll.getExtraHalfDaysSalary());
                    jsonObject.addProperty("halfDays",employeePayroll.getHalfDays());
                    jsonObject.addProperty("halfDaysSalary",employeePayroll.getHalfDaysSalary());
                    jsonObject.addProperty("daysToBeDeducted",employeePayroll.getDaysToBeDeducted());
                    jsonObject.addProperty("lateCount",employeePayroll.getLateCount());
                    jsonObject.addProperty("latePunchDeductionAmount",employeePayroll.getLatePunchDeductionAmt());
                    jsonObject.addProperty("daysToBeDeducted",employeePayroll.getDaysToBeDeducted());
                    jsonObject.addProperty("deductionType",employeePayroll.getDeductionType());
                    jsonObject.addProperty("hoursToBeDeducted",employeePayroll.getHoursToBeDeducted());
                    jsonObject.addProperty("isDayDeduction",employeePayroll.getIsDayDeduction());
                    jsonObject.addProperty("overtimeCount",employeePayroll.getOvertime());
                    jsonObject.addProperty("overtimeAmount",employeePayroll.getOvertimeAmount());

                    if (employee.getWagesOptions() != null) {
                        String[] wagesArr = employee.getWagesOptions().split(",");
                        if (wagesArr.length > 0) {
                            jsonObject.addProperty("netSalaryInHours", Precision.round(employeePayroll.getNetSalaryInHours(), 2));
                            jsonObject.addProperty("netSalaryInDays", Precision.round(employeePayroll.getNetSalaryInDays(), 2));
                        }
                    }

                    List<EmployeePayhead> employeePayheadList = employee.getEmployeePayheadList();
                    JsonArray payheadArray = new JsonArray();
//                    for(LedgerMaster mLedger: list){
//                        for(EmployeePayhead employeePayhead: employeePayheadList) {
//                            JsonObject payheadObject = new JsonObject();
//                            if (mLedger.getLedgerName().equals(employeePayhead.getPayhead().getName())) {
//                                payheadObject.addProperty(utility.getKeyName(mLedger.getLedgerName(), false), mLedger.getLedgerName());
//                                payheadObject.addProperty(utility.getKeyName(mLedger.getLedgerName(), true), mLedger.getId());
//                                payheadObject.addProperty("amount",employeePayhead.getAmount());
//                                payheadObject.addProperty("ledgerName",mLedger.getLedgerName());
//                                payheadArray.add(payheadObject);
//                            }
//                        }
//                    }
                    for(EmployeePayhead employeePayhead: employeePayheadList) {
                        JsonObject payheadObject = new JsonObject();
                        if (!employeePayhead.getPayhead().getIsDefault()) {
                            payheadObject.addProperty(utility.getKeyName(employeePayhead.getPayhead().getName(), false), employeePayhead.getPayhead().getName());
                            payheadObject.addProperty(utility.getKeyName(employeePayhead.getPayhead().getName(), true), employeePayhead.getPayhead().getId());
                            payheadObject.addProperty("amount",employeePayhead.getAmount());
                            payheadObject.addProperty("ledgerName",employeePayhead.getPayhead().getName());
                            payheadArray.add(payheadObject);
                        }
                    }
                    jsonObject.add("payheadArray",payheadArray);
                    responseMessage.add("response", jsonObject);
                    responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
                } else {
                    responseMessage.addProperty("response", "NA");
                    responseMessage.addProperty("message", "Data not found.");
                    responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
                }
            }
            else{
                responseMessage.addProperty("response", "NA");
                responseMessage.addProperty("message", "Employee not found.");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            payrollLogger.error("getCurrentMonthPayslip Exception ===>" + e);
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.addProperty("message", "Failed to load data.");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        return responseMessage;
    }

    public Object insertTranxEmpPayroll(HttpServletRequest request) {
        TranxEmpPayroll mTranxEmpPayroll = null;
        Map<String, String[]> paramMap = request.getParameterMap();
        ResponseMessage responseMessage = new ResponseMessage();
        mTranxEmpPayroll = saveIntoTranxEmployeePayroll(request);
        if (mTranxEmpPayroll != null) {
            // Accounting Postings
            insertIntoLedgerTranxDetails(mTranxEmpPayroll, request);
            responseMessage.setMessage("Employee Payroll created successfully");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } else {
            responseMessage.setMessage("Error in Employee Payroll creation");
            responseMessage.setResponseStatus(HttpStatus.FORBIDDEN.value());
        }
//        }
        return responseMessage;
    }
    public TranxEmpPayroll saveIntoTranxEmployeePayroll(HttpServletRequest request) {
        TranxEmpPayroll mTranxEmpPayroll = new TranxEmpPayroll();
        TranxEmpPayroll object = null;
        try {
            TransactionTypeMaster tranxType = null;
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Branch branch=null;
            Company company=users.getCompany();
            if (users.getBranch() != null) {
                branch = users.getBranch();
                mTranxEmpPayroll.setBranch(branch);
            }
            if(request.getParameterMap().containsKey("list")){
                String jsonStr = request.getParameter("list");
                if(jsonStr != null) {
                    JsonArray payrollList = new JsonParser().parse(jsonStr).getAsJsonArray();
                    for (int i = 0; i < payrollList.size(); i++) {
                        JsonObject mObject = payrollList.get(i).getAsJsonObject();
                        Employee employee = employeeRepository.findById(mObject.get("employeeId").getAsLong()).get();
                        System.out.println("jsonRequest " + mObject.get("month").getAsString());
                        String[] dateValue = mObject.get("month").getAsString().split("-");
                        String userMonth = dateValue[1];
                        String userYear = dateValue[0];
                        String userDay = "01";

                        String newUserDate = userYear + "-" + userMonth + "-" + userDay;
                        TranxEmpPayroll tranxObj = tranxEmpPayrollRepository.checkIfSalaryProcessed(employee.getId(), userMonth);
                        if(tranxObj == null){
                            mTranxEmpPayroll.setCompany(company);
                            mTranxEmpPayroll.setEmployee(employee);
                            mTranxEmpPayroll.setSalaryMonth(LocalDate.parse(newUserDate));
                            List<EmployeePayhead> employeePayheadList = employee.getEmployeePayheadList();
                            List<LedgerMaster> ledgerMasters = new ArrayList<>();
                            for(EmployeePayhead employeePayhead : employeePayheadList){
                                LedgerMaster ledgerMaster = null;
                                if(employeePayhead.getPayhead().getIsDefault() != null && employeePayhead.getPayhead().getIsDefault()){
                                    ledgerMaster = ledgerMasterRepository.findById(employeePayhead.getPayhead().getId()).get();
                                    ledgerMasters.add(ledgerMaster);
                                } else {
                                    ledgerMaster = ledgerMasterRepository.findById(employeePayhead.getPayhead().getId()).get();
                                    ledgerMasters.add(ledgerMaster);
                                }
                            }
                            mTranxEmpPayroll.setLedgers(ledgerMasters);
//                            LedgerMaster BasicSalAc=ledgerMasterRepository.findById(mObject.get("Basic_Salary_A/c_id").getAsLong()).get();
//                            mTranxEmpPayroll.setBasicSalaryLedger(BasicSalAc);
//                            if(mObject.has("Special_Allowance_A/c_id")){
//                                LedgerMaster SpecialAllowanceAc=ledgerMasterRepository.findById(mObject.get("Special_Allowance_A/c_id").getAsLong()).get();
//                                mTranxEmpPayroll.setSpecialAllowanceLedger(SpecialAllowanceAc);
//                                mTranxEmpPayroll.setSpecialAllowance(mObject.get("specialAllowance").getAsDouble());
//                            }
//                            if(mObject.has("PF_A/C_id")){
//                                LedgerMaster PFAc=ledgerMasterRepository.findById(mObject.get("PF_A/C_id").getAsLong()).get();
//                                mTranxEmpPayroll.setPfLedger(PFAc);
//                                mTranxEmpPayroll.setPf(mObject.get("pfAmount").getAsDouble());
//                            }
//                            if(mObject.has("ESIC_A/C_id")){
//                                LedgerMaster ESICAc=ledgerMasterRepository.findById(mObject.get("ESIC_A/C_id").getAsLong()).get();
//                                mTranxEmpPayroll.setEsiLedger(ESICAc);
//                                mTranxEmpPayroll.setEsi(mObject.get("esiAmount").getAsDouble());
//                            }
//                            if(mObject.has("PT_A/C_id")){
//                                LedgerMaster PTAc=ledgerMasterRepository.findById(mObject.get("PT_A/C_id").getAsLong()).get();
//                                mTranxEmpPayroll.setPfTaxLedger(PTAc);
//                                mTranxEmpPayroll.setPfTax(mObject.get("profTax").getAsDouble());
//                            }
//                            if(mObject.has("Insentive_id")) {
//                                LedgerMaster IncentiveAc = ledgerMasterRepository.findById(mObject.get("Insentive_id").getAsLong()).get();
//                                mTranxEmpPayroll.setIncentiveLedger(IncentiveAc);
//                                mTranxEmpPayroll.setIncentive(mObject.get("incentive").getAsDouble());
//                            }
//                            if(mObject.has("Late_Punch-In_id")) {
//                                LedgerMaster LatePunchInAc = ledgerMasterRepository.findById(mObject.get("Late_Punch-In_id").getAsLong()).get();
//                                mTranxEmpPayroll.setLatePunchinLedger(LatePunchInAc);
//                                mTranxEmpPayroll.setLatePunchIn(mObject.get("latePunchDeductionAmount").getAsDouble());
//                            }
                            LedgerMaster employeeLedger=ledgerMasterRepository.findById(mObject.get("emp_ledger_id").getAsLong()).get();
                            mTranxEmpPayroll.setEmpLedger(employeeLedger);
                            mTranxEmpPayroll.setBasic(mObject.get("basic").getAsDouble());
                            mTranxEmpPayroll.setNetPayableAmount(mObject.get("netPayableAmount").getAsDouble());
                            mTranxEmpPayroll.setPayableAmount(mObject.get("payableAmount").getAsDouble());
                            mTranxEmpPayroll.setCreatedAt(LocalDate.now());
                            mTranxEmpPayroll.setIsSalaryProcessed(true);
                            mTranxEmpPayroll.setStatus(true);

                            FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(LocalDate.now());
                            if (fiscalYear != null) {
                                mTranxEmpPayroll.setFinancialYear(fiscalYear.getFiscalYear());
                                mTranxEmpPayroll.setFiscalYear(fiscalYear);
                            }

                            object = tranxEmpPayrollRepository.save(mTranxEmpPayroll);
                        }
                    }
                }
            } else {
                Employee employee = employeeRepository.findById(Long.parseLong(request.getParameter("employeeId"))).get();
                if(request.getParameterMap().containsKey("employeeId")){
                    System.out.println("employeeid exists");
                }
                System.out.println("jsonRequest " + request.getParameter("month"));
                String[] dateValue = request.getParameter("month").split("-");
                String userMonth = dateValue[1];
                String userYear = dateValue[0];
                String userDay = "01";

                String newUserDate = userYear + "-" + userMonth + "-" + userDay;
                TranxEmpPayroll tranxObj = tranxEmpPayrollRepository.checkIfSalaryProcessed(employee.getId(), userMonth);
                if(tranxObj == null){
                    mTranxEmpPayroll.setCompany(company);
                    mTranxEmpPayroll.setEmployee(employee);
                    mTranxEmpPayroll.setSalaryMonth(LocalDate.parse(newUserDate));
                    List<EmployeePayhead> employeePayheadList = employee.getEmployeePayheadList();
                    List<LedgerMaster> ledgerMasters = new ArrayList<>();
                    for(EmployeePayhead employeePayhead : employeePayheadList){
                        LedgerMaster ledgerMaster = null;
                        if(employeePayhead.getPayhead().getIsDefault()!=null&&employeePayhead.getPayhead().getIsDefault()){
                            ledgerMaster = ledgerMasterRepository.findById(employeePayhead.getPayhead().getId()).get();
                            ledgerMasters.add(ledgerMaster);
                        } else {
                            ledgerMaster = ledgerMasterRepository.findById(employeePayhead.getPayhead().getId()).get();
                            ledgerMasters.add(ledgerMaster);
                        }
                    }
                    mTranxEmpPayroll.setLedgers(ledgerMasters);
//                    LedgerMaster BasicSalAc=ledgerMasterRepository.findById(Long.valueOf(request.getParameter("Basic_Salary_A/c_id"))).get();
//                    mTranxEmpPayroll.setBasicSalaryLedger(BasicSalAc);
//                    if(request.getParameterMap().containsKey("Special_Allowance_A/c_id")){
//                        LedgerMaster SpecialAllowanceAc=ledgerMasterRepository.findById(Long.valueOf(request.getParameter("Special_Allowance_A/c_id"))).get();
//                        mTranxEmpPayroll.setSpecialAllowanceLedger(SpecialAllowanceAc);
//                        mTranxEmpPayroll.setSpecialAllowance(Double.valueOf(request.getParameter("specialAllowance")));
//                    }
//                    if(request.getParameterMap().containsKey("PF_A/C_id")){
//                        LedgerMaster PFAc=ledgerMasterRepository.findById(Long.valueOf(request.getParameter("PF_A/C_id"))).get();
//                        mTranxEmpPayroll.setPfLedger(PFAc);
//                        mTranxEmpPayroll.setPf(Double.valueOf(request.getParameter("pfAmount")));
//                    }
//                    if(request.getParameterMap().containsKey("ESIC_A/C_id")){
//                        LedgerMaster ESICAc=ledgerMasterRepository.findById(Long.valueOf(request.getParameter("ESIC_A/C_id"))).get();
//                        mTranxEmpPayroll.setEsiLedger(ESICAc);
//                        mTranxEmpPayroll.setEsi(Double.valueOf(request.getParameter("esiAmount")));
//                    }
//                    if(request.getParameterMap().containsKey("PT_A/C_id")){
//                        LedgerMaster PTAc=ledgerMasterRepository.findById(Long.valueOf(request.getParameter("PT_A/C_id"))).get();
//                        mTranxEmpPayroll.setPfTaxLedger(PTAc);
//                        mTranxEmpPayroll.setPfTax(Double.valueOf(request.getParameter("profTax")));
//                    }
//                    if(request.getParameterMap().containsKey("Insentive_id")) {
//                        LedgerMaster IncentiveAc = ledgerMasterRepository.findById(Long.valueOf(request.getParameter("Insentive_id"))).get();
//                        mTranxEmpPayroll.setIncentiveLedger(IncentiveAc);
//                        mTranxEmpPayroll.setIncentive(Double.valueOf(request.getParameter("incentive")));
//                    }
//                    if(request.getParameterMap().containsKey("Late_Punch-In_id")) {
//                        LedgerMaster LatePunchInAc = ledgerMasterRepository.findById(Long.parseLong(request.getParameter("Late_Punch-In_id"))).get();
//                        mTranxEmpPayroll.setLatePunchinLedger(LatePunchInAc);
//                        mTranxEmpPayroll.setLatePunchIn(Double.parseDouble(request.getParameter("latePunchDeductionAmount")));
//                    }
                    LedgerMaster employeeLedger=ledgerMasterRepository.findById(Long.valueOf(request.getParameter("emp_ledger_id"))).get();
                    mTranxEmpPayroll.setEmpLedger(employeeLedger);
//                    mTranxEmpPayroll.setBasic(Double.valueOf(request.getParameter("basic")));
                    mTranxEmpPayroll.setNetPayableAmount(Double.valueOf(request.getParameter("netPayableAmount")));
                    mTranxEmpPayroll.setPayableAmount(Double.valueOf(request.getParameter("payableAmount")));
                    mTranxEmpPayroll.setCreatedAt(LocalDate.now());
                    mTranxEmpPayroll.setIsSalaryProcessed(true);
                    mTranxEmpPayroll.setStatus(true);

                    FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(LocalDate.now());
                    if (fiscalYear != null) {
                        mTranxEmpPayroll.setFinancialYear(fiscalYear.getFiscalYear());
                        mTranxEmpPayroll.setFiscalYear(fiscalYear);
                    }

                    object = tranxEmpPayrollRepository.save(mTranxEmpPayroll);
                }
            }

        }
        catch (DataIntegrityViolationException e) {
            e.printStackTrace();
//            purInvoiceLogger.error("Error in saveIntoPurchaseInvoice" + e.getMessage());
            System.out.println("Exception:" + e.getMessage());

        }
        catch (Exception e1) {
            e1.printStackTrace();
//            purInvoiceLogger.error("Error in saveIntoPurchaseInvoice" + e1.getMessage());
            System.out.println("Exception:" + e1.getMessage());
        }
        return object;
    }

    public void insertIntoTranxDetailSC(TranxEmpPayroll mPayrollTranx, TransactionTypeMaster tranxType, String type,
                                        String operation,String ledger_type, LedgerMaster ledgerMaster) {
        try {
            /**** New Postings Logic *****/
            Double amt = 0.0;
            if (operation.equalsIgnoreCase("Insert")) {
//                amt = mPayrollTranx.getNetPayableAmount();
//            else amt = mPayrollTranx.getTotalAmount();
                if (ledger_type.equals("emp")) {
                    amt = mPayrollTranx.getNetPayableAmount();
                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getEmpLedger(),
                            tranxType, mPayrollTranx.getEmpLedger().getAssociateGroups(),
                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
                            type, true, tranxType.getTransactionCode(), operation);
                } else {
                    amt = mPayrollTranx.getNetPayableAmount();
                    ledgerCommonPostings.callToPostings(amt, ledgerMaster,
                            tranxType, ledgerMaster.getAssociateGroups(),
                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
                            type, true, tranxType.getTransactionCode(), operation);
                }

//                else if (ledger_type.equals("basic")) {
//                    amt = mPayrollTranx.getBasic();
//                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getBasicSalaryLedger(),
//                            tranxType, mPayrollTranx.getBasicSalaryLedger().getAssociateGroups(),
//                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
//                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
////                    mPayrollTranx.getVendorInvoiceNo(),
//                            type, true, tranxType.getTransactionCode(), operation);
//                } else if (ledger_type.equals("specialAllowance")) {
//                    amt = mPayrollTranx.getSpecialAllowance();
//                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getSpecialAllowanceLedger(),
//                            tranxType, mPayrollTranx.getSpecialAllowanceLedger().getAssociateGroups(),
//                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
//                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
////                    mPayrollTranx.getVendorInvoiceNo(),
//                            type, true, tranxType.getTransactionCode(), operation);
//                } else if (ledger_type.equals("pfAmount")) {
//                    amt = mPayrollTranx.getPf();
//                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getPfLedger(),
//                            tranxType, mPayrollTranx.getPfLedger().getAssociateGroups(),
//                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
//                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
////                    mPayrollTranx.getVendorInvoiceNo(),
//                            type, true, tranxType.getTransactionCode(), operation);
//                } else if (ledger_type.equals("esiAmount")) {
//                    amt = mPayrollTranx.getEsi();
//                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getEsiLedger(),
//                            tranxType, mPayrollTranx.getEsiLedger().getAssociateGroups(),
//                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
//                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
////                    mPayrollTranx.getVendorInvoiceNo(),
//                            type, true, tranxType.getTransactionCode(), operation);
//                } else if (ledger_type.equals("profTax")) {
//                    amt = mPayrollTranx.getPfTax();
//                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getPfTaxLedger(),
//                            tranxType, mPayrollTranx.getBasicSalaryLedger().getAssociateGroups(),
//                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
//                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
////                    mPayrollTranx.getVendorInvoiceNo(),
//                            type, true, tranxType.getTransactionCode(), operation);
//                }
//            else if (ledger_type.equals("incentive")) {
//                    amt = mPayrollTranx.getIncentive();
//                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getIncentiveLedger(),
//                            tranxType, mPayrollTranx.getIncentiveLedger().getAssociateGroups(),
//                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
//                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
////                    mPayrollTranx.getVendorInvoiceNo(),
//                            type, true, tranxType.getTransactionCode(), operation);
//                }
//                else if (ledger_type.equals("latePunchDeductionAmount")) {
//                    amt = mPayrollTranx.getLatePunchIn();
//                    ledgerCommonPostings.callToPostings(amt, mPayrollTranx.getLatePunchinLedger(),
//                            tranxType, mPayrollTranx.getLatePunchinLedger().getAssociateGroups(),
//                            mPayrollTranx.getFiscalYear(), mPayrollTranx.getBranch(), mPayrollTranx.getCompany(),
//                            mPayrollTranx.getCreatedAt(), mPayrollTranx.getId(), "",
////                    mPayrollTranx.getVendorInvoiceNo(),
//                            type, true, tranxType.getTransactionCode(), operation);
//                }
            }
        } catch (Exception e) {
//            purInvoiceLogger.error("Exception->insertIntoTranxDetailSC(method) :" + e.getMessage());
            e.printStackTrace();
            System.out.println("Store Procedure Error " + e.getMessage());
        }
    }

    private void insertIntoLedgerTranxDetails(TranxEmpPayroll mPayrollTranx, HttpServletRequest request) {
        /* start of ledger trasaction details */
        TransactionTypeMaster tranxType = transactionTypeMasterRepository.findByTransactionCodeIgnoreCase("Payroll");

//        generateTransactions.insertIntoTranxsDetails(mPurchaseTranx,tranxType);
        try {
            insertIntoTranxDetailSC(mPayrollTranx, tranxType, "CR", "Insert","emp", null);
            List<LedgerMaster> ledgerMasters = mPayrollTranx.getLedgers();
            for(LedgerMaster ledgerMaster : ledgerMasters){
                List<EmployeePayhead> employeePayheadList = mPayrollTranx.getEmployee().getEmployeePayheadList();
                if(employeePayheadList != null && employeePayheadList.size() > 0) {
                    for(EmployeePayhead employeePayhead : employeePayheadList){
                        insertIntoTranxDetailSC(mPayrollTranx, tranxType, employeePayhead.getIsDeduction()?"DR":"CR", "Insert", ledgerMaster.getSlugName(), ledgerMaster);
                    }
                }
            }

//            insertIntoTranxDetailSC(mPayrollTranx, tranxType, "DR", "Insert","specialAllowance");
//            insertIntoTranxDetailSC(mPayrollTranx, tranxType, "CR", "Insert","pfAmount");
//            insertIntoTranxDetailSC(mPayrollTranx, tranxType, "CR", "Insert","esiAmount");
//            insertIntoTranxDetailSC(mPayrollTranx, tranxType, "CR", "Insert","profTax");
//            insertIntoTranxDetailSC(mPayrollTranx,tranxType,"DR","Insert","incentive");
//            insertIntoTranxDetailSC(mPayrollTranx,tranxType,"CR","Insert","latePunchDeductionAmount");
            // for Sundry Creditors : cr
//            insertIntoTranxDetailPA(mPurchaseTranx, tranxType, "DR", "Insert"); // for Purchase Accounts : dr
//            insertIntoTranxDetailPD(mPurchaseTranx, tranxType, "CR", "Insert"); // for Purchase Discounts : cr
//            insertIntoTranxDetailRO(mPurchaseTranx, tranxType); // for Round Off : cr or dr
//            insertDB(mPurchaseTranx, "AC", tranxType, "DR", "Insert"); // for Additional Charges : dr
//            insertDB(mPurchaseTranx, "DT", tranxType, "DR", "Insert"); // for Duties and Taxes : dr
            /* end of ledger transaction details */
        } catch (Exception e) {
//            purInvoiceLogger.error("Exception->insertIntoLedgerTranxDetails(method) : " + e.getMessage());
            System.out.println("Posting Exception:" + e.getMessage());
            e.printStackTrace();
        }
    }
}