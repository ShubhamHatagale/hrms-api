package com.opethic.hrms.HRMSNew.services.tranx_service.receipt;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.opethic.hrms.HRMSNew.common.GenerateDates;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.common.GenerateSlugs;
import com.opethic.hrms.HRMSNew.common.LedgerCommonPostings;
import com.opethic.hrms.HRMSNew.dto.GenericDTData;
import com.opethic.hrms.HRMSNew.dto.ReciptMasterDTDTO;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.models.report.DayBook;
import com.opethic.hrms.HRMSNew.models.tranx.receipt.TranxReceiptMaster;
import com.opethic.hrms.HRMSNew.models.tranx.receipt.TranxReceiptPerticulars;
import com.opethic.hrms.HRMSNew.models.tranx.receipt.TranxReceiptPerticularsDetails;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerBalanceSummaryRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionPostingsRepository;
import com.opethic.hrms.HRMSNew.repositories.master.*;
import com.opethic.hrms.HRMSNew.repositories.report_repository.DaybookRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.receipt_repository.TranxReceiptMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.receipt_repository.TranxReceiptPerticularsDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.receipt_repository.TranxReceiptPerticularsRepository;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.apache.commons.math3.util.Precision;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class TranxReceiptService {
    @Autowired
    private TranxReceiptMasterRepository repository;
    @Autowired
    private TranxReceiptPerticularsRepository tranxReceiptPerticularsRepository;

    @Autowired
    private TranxReceiptPerticularsDetailsRepository tranxReceiptPerticularsDetailsRepository;
    @Autowired
    private JwtTokenUtil jwtRequestFilter;
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    private GenerateSlugs generateSlugs;
//    @Autowired
//    private TranxSalesInvoiceRepository tranxSalesInvoiceRepository;
    @Autowired
    private LedgerBalanceSummaryRepository ledgerBalanceSummaryRepository;
    @Autowired
    private GenerateFiscalYear generateFiscalYear;
    @Autowired
    private TransactionTypeMasterRepository tranxRepository;
    @Autowired
    private LedgerTransactionPostingsRepository transactionPostingsRepository;
//    @Autowired
//    private TranxCreditNoteNewReferenceRepository tranxCreditNoteNewReferenceRepository;
    @Autowired
    private TransactionStatusRepository transactionStatusRepository;

//    @Autowired
//    private TranxDebitNoteNewReferenceRepository tranxDebitNoteNewReferenceRepository;

    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private DaybookRepository daybookRepository;
    @Autowired
    private LedgerCommonPostings ledgerCommonPostings;
    @Autowired
    private LedgerTransactionPostingsRepository ledgerTransactionPostingsRepository;
    List<Long> dbList = new ArrayList<>(); // for saving all ledgers Id against receipt from DB
    @Autowired
    private Utility utility;
    private static final Logger receiptLogger = LogManager.getLogger(TranxReceiptService.class);
    @Autowired
    private EmployeeRepository employeeRepository;
    @Autowired
    private EmployeePayrollRepository employeePayrollRepository;
    @Autowired
    private TranxEmpPayrollRepository tranxEmpPayrollRepository;
//    @Autowired
//    private TranxPaymentPerticularsRepository tranxPaymentPerticularsRepository;

    public JsonObject receiptLastRecord(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//        Long count = repository.findLastRecord(users.getCompany()().getId());

        Long count = 0L;
        if (users.getBranch() != null) {
            count = repository.findBranchLastRecord(users.getCompany().getId(), users.getBranch().getId());
        } else {
            count = repository.findLastRecord(users.getCompany().getId());
        }


        String serailNo = String.format("%05d", count + 1);// 5 digit serial number
        //first 3 digits of Current month
        GenerateDates generateDates = new GenerateDates();
        String currentMonth = generateDates.getCurrentMonth().substring(0, 3);
        String receiptCode = "RCPT" + currentMonth + serailNo;
        JsonObject result = new JsonObject();
        result.addProperty("message", "success");
        result.addProperty("responseStatus", HttpStatus.OK.value());
        result.addProperty("receipt_sr_no", count + 1);
        result.addProperty("receipt_code", receiptCode);
        return result;
    }

    public JsonObject getSundryDebtorsAndIndirectIncomes(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        
        JsonArray result = new JsonArray();
        JsonObject finalResult = new JsonObject();
        List<LedgerMaster> sundryDebtors = new ArrayList<>();
        List<LedgerMaster> sundryCreditors = new ArrayList<>();
        List<LedgerMaster> list = null;

        if (users.getBranch() != null) {
            sundryCreditors = ledgerMasterRepository.findByCompanyIdAndBranchIdAndPrincipleGroupsIdAndStatus(
                    users.getCompany().getId(), users.getBranch().getId(), 5L, true);
            sundryDebtors = ledgerMasterRepository.findByCompanyIdAndBranchIdAndPrincipleGroupsIdAndStatus(
                    users.getCompany().getId(), users.getBranch().getId(), 1L, true);
            list = ledgerMasterRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
        } else {
            sundryCreditors = ledgerMasterRepository.findByCompanyIdAndPrincipleGroupsIdAndStatusAndBranchIsNull(users.getCompany().getId(), 5L, true);
            sundryDebtors = ledgerMasterRepository.findByCompanyIdAndPrincipleGroupsIdAndStatusAndBranchIsNull(users.getCompany().getId(), 1L, true);
            list = ledgerMasterRepository.findByCompanyIdAndStatus(users.getCompany().getId(), true);
        }
//        sundryDebtors = ledgerMasterRepository.findByCompanyIdAndPrincipleGroupsId(
//                users.getCompany()().getId(), 1L);
//        sundryCreditors = ledgerMasterRepository.findByCompanyIdAndPrincipleGroupsId(
//                users.getCompany()().getId(), 5L);

        /* for Sundry Creditors List */
        if (sundryDebtors.size() > 0) {
            for (LedgerMaster mLedger : sundryDebtors) {
                JsonObject response = new JsonObject();
                response.addProperty("id", mLedger.getId());
                response.addProperty("ledger_name", mLedger.getLedgerName());
                response.addProperty("balancing_method", mLedger.getBalancingMethod() != null ? generateSlugs.getSlug(mLedger.getBalancingMethod().getBalancingMethod()) : "");
                response.addProperty("type", "SD");

                result.add(response);
            }
        }
        if (sundryCreditors.size() > 0) {
            for (LedgerMaster mLedger : sundryCreditors) {
                TranxEmpPayroll tranxEmpPayroll = null;
                JsonObject response = new JsonObject();
                String yearMonth = null;
                String monthValue = null;
                if (request.getParameterMap().containsKey("fromMonth") && !request.getParameter("fromMonth").equals("")) {
                    String[] fromMonth = request.getParameter("fromMonth").split("-");
                    int userMonth = Integer.parseInt(fromMonth[1]);
                    int userYear = Integer.parseInt(fromMonth[0]);
                    monthValue =userMonth < 10 ? "0"+userMonth : String.valueOf(userMonth);
                    yearMonth = userYear + "-" + monthValue;
                } else {
                    monthValue = LocalDate.now().getMonthValue() < 10 ? "0"+LocalDate.now().getMonthValue() : String.valueOf(LocalDate.now().getMonthValue());
                    yearMonth = LocalDate.now().getYear() + "-" + monthValue;
                }
                response.addProperty("id", mLedger.getId());
                response.addProperty("employeeId", mLedger.getEmployee().getId());
                Employee employee = employeeRepository.findByIdAndStatus(mLedger.getEmployee().getId(), true);
                try {
                    tranxEmpPayroll = tranxEmpPayrollRepository.checkIfSalaryProcessed(employee.getId(), monthValue);
                    if(employee != null){

                        EmployeePayroll employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(employee.getId(),
                                yearMonth);
                        if (employeePayroll != null) {
                            response.addProperty("noDaysPresent", Precision.round(employeePayroll.getNoDaysPresent(), 2));
                            response.addProperty("neySalary",employeePayroll.getNetSalary());
                            response.addProperty("payableAmount", Precision.round(employeePayroll.getPayableAmount(), 2));
                            response.addProperty("payrollDate",employeePayroll.getYearMonth());
                            response.addProperty("month", yearMonth);
                            response.addProperty("employeeId", employeePayroll.getEmployee().getId());
                            response.addProperty("employeeName", utility.getEmployeeName(employeePayroll.getEmployee()));
                            response.addProperty("basic", Precision.round(employeePayroll.getBasic(), 2));
                            response.addProperty("specialAllowance", Precision.round(employeePayroll.getSpecialAllowance(),2));
                            response.addProperty("netSalary", Precision.round(employeePayroll.getNetSalary(), 2));
                            response.addProperty("pfPercentage", Precision.round(employeePayroll.getPfPer(), 2));
                            response.addProperty("pfAmount", Precision.round(employeePayroll.getPf(), 2));
                            response.addProperty("esiPercentage", Precision.round(employeePayroll.getEsiPer(), 2));
                            response.addProperty("esiAmount", Precision.round(employeePayroll.getEsi(), 2));
                            response.addProperty("profTax", Precision.round(employeePayroll.getPfTax(), 2));
                            response.addProperty("payableAmount", Precision.round(employeePayroll.getPayableAmount(), 2));
                            response.addProperty("incentive", Precision.round(employeePayroll.getIncentive(), 2));
                            response.addProperty("netPayableAmount", Precision.round(employeePayroll.getNetPayableAmount(), 2));
                            response.addProperty("latePunchDeductionAmount", Precision.round(employeePayroll.getLatePunchDeductionAmt(), 2));


                            List<EmployeePayhead> employeePayheadList = employee.getEmployeePayheadList();
                            for(EmployeePayhead employeePayhead: employeePayheadList) {
                                if (mLedger.getLedgerName().equals(employeePayhead.getPayhead().getName())) {
                                    response.addProperty(utility.getKeyName(mLedger.getLedgerName(), false), mLedger.getLedgerName());
                                    response.addProperty(utility.getKeyName(mLedger.getLedgerName(), true), mLedger.getId());
                                }
                            }
                        }
                    }
                    response.addProperty("ledger_name", mLedger.getLedgerName());
                    response.addProperty("isSalaryProcessed",tranxEmpPayroll != null ? tranxEmpPayroll.getIsSalaryProcessed() : false);
                    response.addProperty("emp_ledger_id", mLedger.getId());
                    response.addProperty("balancing_method", generateSlugs.getSlug(mLedger.getBalancingMethod().getBalancingMethod()));
                    response.addProperty("type", "SC");

                    result.add(response);
                }catch (Exception e){
                    System.out.println(e);
                }

            }
        }
        List<LedgerMaster> indirectIncomes = new ArrayList<>();
        indirectIncomes = ledgerMasterRepository.findByCompanyIdAndPrinciplesIdAndStatus(users.getCompany().getId(), 9L, true);
        if (indirectIncomes.size() > 0) {
            for (LedgerMaster mLedger : indirectIncomes) {
                if (!mLedger.getLedgerName().equalsIgnoreCase("Purchase Discount")) {
                    JsonObject response = new JsonObject();
                    response.addProperty("id", mLedger.getId());
                    response.addProperty("ledger_name", mLedger.getLedgerName());
                    response.addProperty("balancing_method", "NA");
                    response.addProperty("type", "IC");
                    result.add(response);
                }
            }
        }
        /***** Current assests ****/
        List<LedgerMaster> currentAssets = new ArrayList<>();
        currentAssets = ledgerMasterRepository.findByCompanyIdAndPrinciplesIdAndStatus(users.getCompany().getId(), 3L, true);
        if (currentAssets.size() > 0) {
            for (LedgerMaster mLedger : currentAssets) {
                if (!mLedger.getUniqueCode().equalsIgnoreCase("SUDR")) {
                    JsonObject response = new JsonObject();
                    response.addProperty("id", mLedger.getId());
                    response.addProperty("ledger_name", mLedger.getLedgerName());
                    response.addProperty("balancing_method", "on-account");
                    response.addProperty("type", "CA");
                    result.add(response);
                }
            }
        }
        finalResult.addProperty("message", "success");
        finalResult.addProperty("responseStatus", HttpStatus.OK.value());
        finalResult.add("list", result);
        return finalResult;
    }

    public JsonObject createReceipt(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonObject response = new JsonObject();
        TranxReceiptMaster tranxReceipt = new TranxReceiptMaster();
        Branch branch = null;
        if (users.getBranch() != null) {
            branch = users.getBranch();
            tranxReceipt.setBranch(branch);
        }
        Company outlet = users.getCompany();
        tranxReceipt.setCompany(outlet);
        LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
        tranxReceipt.setTranscationDate(tranxDate);
        tranxReceipt.setStatus(true);
        /*     fiscal year mapping  */
        FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
        if (fiscalYear != null) {
            tranxReceipt.setFiscalYear(fiscalYear);
            tranxReceipt.setFinancialYear(fiscalYear.getFiscalYear());
        }
        tranxReceipt.setReceiptSrNo(Long.parseLong(request.getParameter("receipt_sr_no")));
        if (paramMap.containsKey("narration")) tranxReceipt.setNarrations(request.getParameter("narration"));
        else {
            tranxReceipt.setNarrations(request.getParameter("NA"));
        }
        tranxReceipt.setReceiptNo(request.getParameter("receipt_code"));
        tranxReceipt.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
        tranxReceipt.setCreatedBy(users.getId());
        TranxReceiptMaster tranxReceiptMaster = repository.save(tranxReceipt);
        try {
            double total_amt = 0.0;
            String jsonStr = request.getParameter("row");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                String crdrType = "";
                /*Receipt Master */
                JsonObject receiptRow = row.get(i).getAsJsonObject();
                /*Receipt Perticulars */
                TranxReceiptPerticulars tranxReceiptPerticulars = new TranxReceiptPerticulars();
                LedgerMaster ledgerMaster = null;
                tranxReceiptPerticulars.setBranch(branch);
                tranxReceiptPerticulars.setCompany(outlet);
                tranxReceiptPerticulars.setStatus(true);
                ledgerMaster = ledgerMasterRepository.findByIdAndStatus(receiptRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                if (ledgerMaster != null) tranxReceiptPerticulars.setLedgerMaster(ledgerMaster);
                tranxReceiptPerticulars.setTranxReceiptMaster(tranxReceiptMaster);
                tranxReceiptPerticulars.setType(receiptRow.get("type").getAsString());
                tranxReceiptPerticulars.setLedgerType(receiptRow.get("perticulars").getAsJsonObject().get("type").getAsString());
                tranxReceiptPerticulars.setLedgerName(receiptRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());
                crdrType = receiptRow.get("type").getAsString();
                if (crdrType.equalsIgnoreCase("dr")) {
                    tranxReceiptPerticulars.setDr(receiptRow.get("paid_amt").getAsDouble());
                }
                if (crdrType.equalsIgnoreCase("cr")) {
                    tranxReceiptPerticulars.setCr(receiptRow.get("paid_amt").getAsDouble());
                }
                if (receiptRow.has("bank_payment_no")) {
                    tranxReceiptPerticulars.setPaymentTranxNo(receiptRow.get("bank_payment_no").getAsString());
                }
                if (receiptRow.has("bank_payment_type")) {
                    tranxReceiptPerticulars.setPaymentMethod(receiptRow.get("bank_payment_type").getAsString());
                }
                tranxReceiptPerticulars.setCreatedBy(users.getId());
                TranxReceiptPerticulars mParticular = tranxReceiptPerticularsRepository.save(tranxReceiptPerticulars);
                total_amt = receiptRow.get("paid_amt").getAsDouble();

                /*Receipt Perticulars Details*/
                JsonObject perticulars = receiptRow.get("perticulars").getAsJsonObject();
                JsonArray billList = new JsonArray();
                if (perticulars.has("billids")) {
                    billList = perticulars.get("billids").getAsJsonArray();
                    if (billList != null && billList.size() > 0) {
                        for (int j = 0; j < billList.size(); j++) {
                            TranxReceiptPerticularsDetails tranxRptDetails = new TranxReceiptPerticularsDetails();
                            JsonObject jsonBill = billList.get(j).getAsJsonObject();
//                            TranxSalesInvoice mSaleInvoice = null;
                            tranxRptDetails.setBranch(branch);
                            tranxRptDetails.setCompany(outlet);

                            if (ledgerMaster != null) tranxRptDetails.setLedgerMaster(ledgerMaster);
                            tranxRptDetails.setTranxReceiptMaster(tranxReceiptMaster);
                            tranxRptDetails.setTranxReceiptPerticulars(mParticular);
                            tranxRptDetails.setStatus(true);
                            tranxRptDetails.setTranxInvoiceId(jsonBill.get("invoice_id").getAsLong());
                            tranxRptDetails.setType(jsonBill.get("source").getAsString());
                            tranxRptDetails.setTotalAmt(jsonBill.get("amount").getAsDouble());
                            tranxRptDetails.setPaidAmt(jsonBill.get("paid_amt").getAsDouble());
                            tranxRptDetails.setTransactionDate(LocalDate.parse(jsonBill.get("invoice_date").getAsString()));
                            tranxRptDetails.setTranxNo(jsonBill.get("invoice_no").getAsString());
                            tranxRptDetails.setCreatedBy(users.getId());
                            tranxReceiptPerticularsDetailsRepository.save(tranxRptDetails);
                        }
                    }
                }

                TranxReceiptPerticulars mReceipt = tranxReceiptPerticularsRepository.save(tranxReceiptPerticulars);
                insertIntoPostings(mReceipt, total_amt, crdrType, "Insert");//Accounting Postings
            }
            response.addProperty("message", "Receipt successfully done..");
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            receiptLogger.error("Error in createReceipt :->" + e.getMessage());
            response.addProperty("message", "Error in Receipt creation");
            response.addProperty("responseStatus", HttpStatus.CONFLICT.value());
        }
        return response;
    }

    /* Accounting Postings of Receipt Vouchers  */
    private void insertIntoPostings(TranxReceiptPerticulars mReceipt, double total_amt, String crdrType, String operation) {
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("RCPT");
        try {
            /* for Sundry Debtors  */

            /**** New Postings Logic *****/
            ledgerCommonPostings.callToPostings(total_amt, mReceipt.getLedgerMaster(), tranxType,
                    mReceipt.getLedgerMaster().getAssociateGroups(),
                    mReceipt.getTranxReceiptMaster().getFiscalYear(), mReceipt.getBranch(),
                    mReceipt.getCompany(), mReceipt.getTranxReceiptMaster().getTranscationDate(),
                    mReceipt.getTranxReceiptMaster().getId(),
                    mReceipt.getTranxReceiptMaster().getReceiptNo(), crdrType, true,
                    "Receipt", operation);
            /**** Save into Day Book ****/
            if (crdrType.equalsIgnoreCase("cr")) {
                saveIntoDayBook(mReceipt);
            }

        } catch (Exception e) {
            e.printStackTrace();
            receiptLogger.error("Error in insertIntoPostings :->" + e.getMessage());
        }
    }

    private void saveIntoDayBook(TranxReceiptPerticulars mReceipt) {
        DayBook dayBook = new DayBook();
        dayBook.setCompany(mReceipt.getCompany());
        if (mReceipt.getBranch() != null) dayBook.setBranch(mReceipt.getBranch());
        dayBook.setAmount(mReceipt.getCr());
        dayBook.setTranxDate(mReceipt.getTranxReceiptMaster().getTranscationDate());
        dayBook.setParticulars(mReceipt.getLedgerMaster().getLedgerName());
        dayBook.setVoucherNo(mReceipt.getTranxReceiptMaster().getReceiptNo());
        dayBook.setVoucherType("Receipt");
        dayBook.setStatus(true);
        try {
            daybookRepository.save(dayBook);
        } catch (Exception e) {
            receiptLogger.error("Error in Save into DayBook->" + e.getMessage());
        }
    }

    public Object DTReceiptList(Map<String, String> request, HttpServletRequest httpServletRequest) {
        Integer from = Integer.parseInt(request.get("from"));
        Integer to = Integer.parseInt(request.get("to"));
        String searchText = request.get("searchText");
        Users users = jwtRequestFilter.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        GenericDTData genericDTData = new GenericDTData();
        List<TranxReceiptMaster> tranxReceiptMasterList = new ArrayList<>();
        List<ReciptMasterDTDTO> reciptMasterDTDTOList = new ArrayList<>();
        String query = "";
        try {
            if (users.getBranch() != null) {
//                receipt = repository.findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch()().getId(), true);
//                query = "SELECT * FROM `tranx_receipt_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND branch_id="+users.getBranch()().getId()+" " +
//                        "AND tranx_receipt_master_tbl.status=1";
                query = "SELECT m.*, p.* FROM tranx_receipt_master_tbl m LEFT JOIN tranx_receipt_perticulars_tbl p " +
                        "ON m.id=p.tranx_receipt_master_id WHERE p.company_id="+users.getCompany().getId()+" AND " +
                        "p.branch_id="+users.getBranch().getId()+" AND m.status=1 GROUP BY m.receipt_no";
            } else {
//                receipt = repository.findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
//                query = "SELECT * FROM `tranx_receipt_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND tranx_receipt_master_tbl.status=1";
                query = "SELECT m.*, p.* FROM tranx_receipt_master_tbl m LEFT JOIN tranx_receipt_perticulars_tbl p " +
                        "ON m.id=p.tranx_receipt_master_id WHERE p.company_id="+users.getCompany().getId()+" AND m.status=1 GROUP BY m.receipt_no";
            }


            if (!searchText.equalsIgnoreCase("")) {
                query = query + " AND (receipt_no LIKE '%" + searchText + "%' OR narration LIKE '%" +
                        searchText + "%')";
            }

            String jsonToStr = request.get("sort");
            JsonObject jsonObject = new Gson().fromJson(jsonToStr, JsonObject.class);
            if (!jsonObject.get("colId").toString().equalsIgnoreCase("null") &&
                    jsonObject.get("colId").toString() != null) {
                System.out.println(" ORDER BY " + jsonObject.get("colId").toString());
                String sortBy = jsonObject.get("colId").toString();
                query = query + " ORDER BY " + sortBy;
                if (jsonObject.get("isAsc").getAsBoolean()) {
                    query = query + " ASC";
                } else {
                    query = query + " DESC";
                }
            }
            String query1 = query;
            Integer endLimit = to - from;
            query = query + " LIMIT " + from + ", " + endLimit;
            System.out.println("query " + query);

            Query q = entityManager.createNativeQuery(query, TranxReceiptMaster.class);
            Query q1 = entityManager.createNativeQuery(query1, TranxReceiptMaster.class);

            tranxReceiptMasterList = q.getResultList();
            System.out.println("Limit total rows " + tranxReceiptMasterList);

            for (TranxReceiptMaster tranxReceiptMaster : tranxReceiptMasterList) {
                reciptMasterDTDTOList.add(convertToDTDTO(tranxReceiptMaster));
            }

//            List<Allowance> allowanceArrayList = new ArrayList<>();
//            allowanceArrayList = q1.getResultList();
//            System.out.println("total rows " + allowanceArrayList.size());
//
//            genericDTData.setRows(reciptMasterDTDTOList);
//            genericDTData.setTotalRows(allowanceArrayList.size());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            genericDTData.setRows(reciptMasterDTDTOList);
            genericDTData.setTotalRows(0);
        }
        return genericDTData;
    }

    private ReciptMasterDTDTO convertToDTDTO(TranxReceiptMaster rMaster) {
        ReciptMasterDTDTO receiptMaster = new ReciptMasterDTDTO();
        receiptMaster.setId(rMaster.getId());
        receiptMaster.setReceiptNo(rMaster.getReceiptNo());
        receiptMaster.setReceiptSrNo(rMaster.getReceiptSrNo());
        receiptMaster.setTranxReceiptPerticulars(rMaster.getTranxReceiptPerticulars().size() > 0 ? rMaster.getTranxReceiptPerticulars().get(0).getLedgerName() : "");
        receiptMaster.setTranscationDate(rMaster.getTranscationDate().toString());
        receiptMaster.setNarrations(rMaster.getNarrations());
        receiptMaster.setTotalAmt(rMaster.getTotalAmt());
        receiptMaster.setStatus(rMaster.getStatus());
        receiptMaster.setCreatedAt(String.valueOf(rMaster.getCreatedAt()));
        return receiptMaster;
    }

    public JsonObject receiptListbyCompany(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<TranxReceiptMaster> receipt = new ArrayList<>();
        if (users.getBranch() != null) {
            receipt = repository.findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch().getId(), true);
        } else {
            receipt = repository.findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
        }

        for (TranxReceiptMaster invoices : receipt) {
            try {
                JsonObject response = new JsonObject();
                response.addProperty("id", invoices.getId());
                response.addProperty("receipt_code", invoices.getReceiptNo());
                response.addProperty("transaction_dt", invoices.getTranscationDate().toString());
                response.addProperty("narration", invoices.getNarrations() != null ? invoices.getNarrations() : "");
//            response.addProperty("custName",invoices.getCustName().toString());
                response.addProperty("receipt_sr_no", invoices.getReceiptSrNo());
                List<TranxReceiptPerticulars> tranxReceiptPerticulars = tranxReceiptPerticularsRepository.findLedgerName(invoices.getId(), users.getCompany().getId(), true);

                response.addProperty("total_amount", invoices.getTotalAmt());
                response.addProperty("ledger_name", tranxReceiptPerticulars != null &&
                        tranxReceiptPerticulars.size() > 0 ? tranxReceiptPerticulars.get(0).getLedgerName() : "");
                response.addProperty("narriation", invoices.getNarrations());
                result.add(response);
            }catch (Exception e){
                e.printStackTrace();
            }
        }

        JsonObject output = new JsonObject();
        output.addProperty("message", "success");
        output.addProperty("responseStatus", HttpStatus.OK.value());
        output.add("data", result);
        return output;
    }

    public JsonObject updateReceipt(HttpServletRequest request) {
        JsonObject response = null;
        try {
            Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Map<String, String[]> paramMap = request.getParameterMap();
            TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("RCPT");
            TranxReceiptMaster tranxReceipt = repository.findByIdAndStatus(Long.parseLong(request.getParameter("receiptId")), true);
//        dbList = transactionPostingsRepository.findByTransactionId(tranxReceipt.getId(), tranxType.getId());
            response = new JsonObject();
//        TranxReceiptMaster tranxReceipt = new TranxReceiptMaster();
            Branch branch = null;
            if (users.getBranch() != null) {
                branch = users.getBranch();
                tranxReceipt.setBranch(branch);
            }
            Company outlet = users.getCompany();
            tranxReceipt.setCompany(outlet);
            tranxReceipt.setCreatedBy(users.getId());
//        tranxReceipt.setBranch(branch);
            // tranxReceipt.setCompany(outlet);
            LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
            tranxReceipt.setTranscationDate(tranxDate);
            //   tranxReceipt.setStatus(true);
            /*     fiscal year mapping  */

            FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
            if (fiscalYear != null) {
                tranxReceipt.setFiscalYear(fiscalYear);
                tranxReceipt.setFinancialYear(fiscalYear.getFiscalYear());
            }
//                tranxReceipt.setPaymentDate(tranxDate);
            tranxReceipt.setReceiptSrNo(Long.parseLong(request.getParameter("receipt_sr_no")));
            if (paramMap.containsKey("narration")) tranxReceipt.setNarrations(request.getParameter("narration"));
            else {
                tranxReceipt.setNarrations(request.getParameter("NA"));
            }
            tranxReceipt.setReceiptNo(request.getParameter("receipt_code"));
            tranxReceipt.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
            tranxReceipt.setCreatedBy(users.getId());
            //  tranxReceipt.setUpdatedBy(users.getId());
            TranxReceiptMaster tranxReceiptMaster = repository.save(tranxReceipt);
            try {
                double total_amt = 0.0;
                String jsonStr = request.getParameter("row");
                JsonParser parser = new JsonParser();
                JsonArray row = parser.parse(jsonStr).getAsJsonArray();
                for (int i = 0; i < row.size(); i++) {
                    /*Receipt Master */

//                LedgerMaster mLedger = null;
                    JsonObject receiptRow = row.get(i).getAsJsonObject();
                    System.out.println("receiptRow::" + receiptRow);

                    /*Receipt Perticulars */
                    TranxReceiptPerticulars tranxReceiptPerticulars = null;
                    Long detailsId = 0L;
                    if (receiptRow.has("details_id")) detailsId = receiptRow.get("details_id").getAsLong();
                    if (detailsId != 0) {
                        tranxReceiptPerticulars = tranxReceiptPerticularsRepository.findByIdAndStatus(detailsId, true);
                    } else {
                        tranxReceiptPerticulars = new TranxReceiptPerticulars();
                        tranxReceiptPerticulars.setStatus(true);
                    }
//                TranxReceiptPerticulars tranxReceiptPerticulars = new TranxReceiptPerticulars();
                    LedgerMaster ledgerMaster = null;
                    tranxReceiptPerticulars.setBranch(branch);
                    tranxReceiptPerticulars.setCompany(outlet);
                    ledgerMaster = ledgerMasterRepository.findByIdAndStatus(receiptRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                    if (ledgerMaster != null) tranxReceiptPerticulars.setLedgerMaster(ledgerMaster);
                    tranxReceiptPerticulars.setTranxReceiptMaster(tranxReceiptMaster);
                    tranxReceiptPerticulars.setType(receiptRow.get("type").getAsJsonObject().get("type").getAsString());
                    tranxReceiptPerticulars.setLedgerType(receiptRow.get("perticulars").getAsJsonObject().get("type").getAsString());
                    tranxReceiptPerticulars.setLedgerName(receiptRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());

                    if (receiptRow.get("type").getAsJsonObject().get("type").getAsString().equalsIgnoreCase("dr")) {
                        tranxReceiptPerticulars.setDr(receiptRow.get("paid_amt").getAsDouble());
                    }
                    if (receiptRow.get("type").getAsJsonObject().get("type").getAsString().equalsIgnoreCase("cr")) {
                        tranxReceiptPerticulars.setCr(receiptRow.get("paid_amt").getAsDouble());
                    }
                    if (receiptRow.has("bank_payment_no")) {
                        tranxReceiptPerticulars.setPaymentTranxNo(receiptRow.get("bank_payment_no").getAsString());
                    }
                    if (receiptRow.has("bank_payment_type")) {
                        tranxReceiptPerticulars.setPaymentMethod(receiptRow.get("bank_payment_type").getAsString());
                    }
                    tranxReceiptPerticulars.setCreatedBy(users.getId());
                    //    tranxReceiptPerticulars.setUpdatedBy(users.getId());
                    TranxReceiptPerticulars mParticular = tranxReceiptPerticularsRepository.save(tranxReceiptPerticulars);

                    total_amt = receiptRow.get("paid_amt").getAsDouble();
                    tranxReceiptPerticulars.setPaymentAmount(total_amt);
//                tranxReceiptPerticulars.getPaymentAmount(total

                    /*Receipt Perticulars Details*/

                    JsonObject perticulars = receiptRow.get("perticulars").getAsJsonObject();
                    JsonArray billList = new JsonArray();
                    if (perticulars.has("billids")) {
                        billList = perticulars.get("billids").getAsJsonArray();
                        if (billList != null && billList.size() > 0) {
                            for (int j = 0; j < billList.size(); j++) {
                                TranxReceiptPerticularsDetails tranxRptDetails = new TranxReceiptPerticularsDetails();
                                JsonObject jsonBill = billList.get(j).getAsJsonObject();
//                            TranxSalesInvoice mSaleInvoice = null;
                           /* tranxRptDetails.setBranch(branch);
                            tranxRptDetails.setCompany(outlet);
*/
                                if (ledgerMaster != null) tranxRptDetails.setLedgerMaster(ledgerMaster);
                                tranxRptDetails.setTranxReceiptMaster(tranxReceiptMaster);
                                tranxRptDetails.setTranxReceiptPerticulars(mParticular);
                                // tranxRptDetails.setStatus(true);
                                tranxRptDetails.setTranxInvoiceId(jsonBill.get("invoice_id").getAsLong());
                                tranxRptDetails.setType(jsonBill.get("source").getAsString());
                                tranxRptDetails.setTotalAmt(jsonBill.get("amount").getAsDouble());
                                tranxRptDetails.setPaidAmt(jsonBill.get("paid_amt").getAsDouble());
                                tranxRptDetails.setTransactionDate(LocalDate.parse(jsonBill.get("invoice_date").getAsString()));
                                tranxRptDetails.setTranxNo(jsonBill.get("invoice_no").getAsString());
                                tranxRptDetails.setCreatedBy(users.getId());
//                            if (jsonBill.get("source").getAsString().equalsIgnoreCase("sales_invoice")) {
//                                mSaleInvoice = tranxSalesInvoiceRepository.findByIdAndStatus(jsonBill.get("invoice_id").getAsLong(), true);
//                                if (jsonBill.has("remaining_amt")) {
//                                    mSaleInvoice.setBalance(jsonBill.get("remaining_amt").getAsDouble());
//                                    tranxSalesInvoiceRepository.save(mSaleInvoice);
//                                }
//                            } else if (jsonBill.get("source").getAsString().equalsIgnoreCase("credit_note")) {
//                                TranxCreditNoteNewReferenceMaster tranxCreditNoteNewReference = tranxCreditNoteNewReferenceRepository.findByIdAndStatus(jsonBill.get("invoice_id").getAsLong(), true);
//                                if (jsonBill.has("remaining_amt")) {
//                                    Double mbalance = jsonBill.get("remaining_amt").getAsDouble();
//                                    tranxCreditNoteNewReference.setBalance(mbalance);
//                                    if (mbalance == 0.0) {
//                                        TransactionStatus transactionStatus = transactionStatusRepository.findByStatusNameAndStatus("closed", true);
//                                        tranxCreditNoteNewReference.setTransactionStatus(transactionStatus);
//                                        tranxCreditNoteNewReferenceRepository.save(tranxCreditNoteNewReference);
//                                    }
//                                }
//                            } else if (jsonBill.get("source").getAsString().equalsIgnoreCase("debit_note")) {
//                                TranxDebitNoteNewReferenceMaster tranxDebitNoteNewReference = tranxDebitNoteNewReferenceRepository.findByIdAndStatus(jsonBill.get("invoice_id").getAsLong(), true);
//
////                                tranxRptDetails.setTotalAmt(jsonBill.get("total_amt").getAsDouble());
//
//                                if (jsonBill.has("remaining_amt")) {
//                                    Double mbalance = jsonBill.get("remaining_amt").getAsDouble();
//                                    tranxDebitNoteNewReference.setBalance(mbalance);
//                                    if (mbalance == 0.0) {
//                                        TransactionStatus transactionStatus = transactionStatusRepository.findByStatusNameAndStatus("closed", true);
//                                        tranxDebitNoteNewReference.setTransactionStatus(transactionStatus);
//                                        tranxDebitNoteNewReferenceRepository.save(tranxDebitNoteNewReference);
//                                    }
//                                }
//                            }
                                // save into tranxRptDetails
                                tranxReceiptPerticularsDetailsRepository.save(tranxRptDetails);
                            }
                        }
                    }

                    //  TranxReceiptPerticulars mReceipt = tranxReceiptPerticularsRepository.save(tranxReceiptPerticulars);
                    updateIntoPostings(mParticular, total_amt, detailsId);
                }

                response.addProperty("message", "Receipt successfully updated..");
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                receiptLogger.error("Error in update Receipt :->" + e.getMessage());
                response.addProperty("message", "Error in Receipt updation");
                response.addProperty("responseStatus", HttpStatus.OK.value());
            }
//            return response;
        } catch (Exception e) {
            e.printStackTrace();
            receiptLogger.error("Error in update Receipt :->" + e.getMessage());
        }
        return response;
    }


    public JsonObject getReceiptById(HttpServletRequest request) {

        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<TranxReceiptPerticulars> list = new ArrayList<>();
        JsonArray units = new JsonArray();
        List<TranxReceiptPerticularsDetails> detailsList = new ArrayList<>();
        JsonObject finalResult = new JsonObject();

        try {
            Long receiptId = Long.parseLong(request.getParameter("receiptId"));
            TranxReceiptMaster tranxReceiptMaster = repository.findByIdAndCompanyIdAndStatus(receiptId, users.getCompany().getId(), true);

            list = tranxReceiptPerticularsRepository.findByTranxReceiptMasterIdAndStatus(tranxReceiptMaster.getId(), true);
//            detailsList = tranxReceiptPerticularsDetailsRepository.findByIdAndStatus(tranxReceiptMaster.getId(), true);
            finalResult.addProperty("receiptId",tranxReceiptMaster.getId());
            finalResult.addProperty("receipt_no", tranxReceiptMaster.getReceiptNo());
            finalResult.addProperty("receipt_sr_no", tranxReceiptMaster.getReceiptSrNo());
            finalResult.addProperty("tranx_date", tranxReceiptMaster.getTranscationDate().toString());
            finalResult.addProperty("total_amt", tranxReceiptMaster.getTotalAmt());
            finalResult.addProperty("narrations", tranxReceiptMaster.getNarrations());

            JsonArray row = new JsonArray();
            if (list.size() > 0) {
                for (TranxReceiptPerticulars mdetails : list) {
//                  List<TranxReceiptPerticulars> receiptPerticulars1=tranxReceiptPerticularsRepository.findByIdAndStatus(mdetails.getId(),true);

                    JsonObject rpdetails = new JsonObject();
                    rpdetails.addProperty("details_id", mdetails.getId());
                    rpdetails.addProperty("type", mdetails.getType());
                    rpdetails.addProperty("ledger_type", mdetails.getLedgerType());
                    rpdetails.addProperty("ledger_name", mdetails.getLedgerName());
                    rpdetails.addProperty("dr", mdetails.getDr());
                    rpdetails.addProperty("cr", mdetails.getCr());
                    rpdetails.addProperty("paymentMethod", mdetails.getPaymentMethod());
                    rpdetails.addProperty("paymentTranxNo", mdetails.getPaymentTranxNo());
                    rpdetails.addProperty("ledger_id", mdetails.getLedgerMaster().getId());
//                  rpdetails.add("receipt_perticulars",receiptper);
                    row.add(rpdetails);
                }
            }

            finalResult.addProperty("message", "success");
            finalResult.addProperty("responseStatus", HttpStatus.OK.value());

            finalResult.add("perticulars", row);
//            finalResult.add("receipt_perticulars_details", rowDetails);

        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            receiptLogger.error("Error in getReceiptById" + e.getMessage());
            System.out.println(e.getMessage());
            e.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.CONFLICT.value());
        } catch (Exception e1) {
            e1.printStackTrace();
            receiptLogger.error("Error in getReceiptById" + e1.getMessage());
            System.out.println(e1.getMessage());
            e1.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return finalResult;
    }

    private void updateIntoPostings(TranxReceiptPerticulars mReceipt, double total_amt, Long detailsId) {
        LedgerMaster sundryCreditors = null;
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("RCPT");
        try {
            /* for Sundry Debtors  */
            if (mReceipt.getType().equalsIgnoreCase("cr")) {
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.
                            findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(mReceipt.getLedgerMaster().getId(),
                                    tranxType.getId(),
                                    mReceipt.getTranxReceiptMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(mReceipt.getTranxReceiptMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    //   transactionDetailsRepository.insertIntoLegerTranxDetailsPosting(mReceipt.getLedgerMaster().getFoundations().getId(), mReceipt.getLedgerMaster().getPrinciples() != null ? mReceipt.getLedgerMaster().getPrinciples().getId() : null, mReceipt.getLedgerMaster().getPrincipleGroups() != null ? mReceipt.getLedgerMaster().getPrincipleGroups().getId() : null, null, tranxType.getId(), mReceipt.getLedgerMaster().getBalancingMethod() != null ? mReceipt.getLedgerMaster().getBalancingMethod().getId() : null, mReceipt.getBranch()()() != null ? mReceipt.getBranch()()().getId() : null, mReceipt.getCompany()().getId(), "NA", 0.0, total_amt, mReceipt.getTranxReceiptMaster().getTranscationDate(), null, mReceipt.getId(), tranxType.getTransactionName(), mReceipt.getLedgerMaster().getUnderPrefix(), mReceipt.getTranxReceiptMaster().getFinancialYear(), mReceipt.getCreatedBy(), mReceipt.getLedgerMaster().getId(), mReceipt.getTranxReceiptMaster().getReceiptNo());
                    ledgerCommonPostings.callToPostings(total_amt, mReceipt.getLedgerMaster(), tranxType,
                            mReceipt.getLedgerMaster().getAssociateGroups(),
                            mReceipt.getTranxReceiptMaster().getFiscalYear(), mReceipt.getBranch(),
                            mReceipt.getCompany(), mReceipt.getTranxReceiptMaster().getTranscationDate(),
                            mReceipt.getTranxReceiptMaster().getId(),
                            mReceipt.getTranxReceiptMaster().getReceiptNo(),
                            "CR", true, "Receipt", "Insert");
                }
            } else {
                //  Boolean isContains = dbList.contains(mReceipt.getLedgerMaster().getPrinciples().getId());
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.
                            findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(mReceipt.getLedgerMaster().getId(),
                                    tranxType.getId(), mReceipt.getTranxReceiptMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(mReceipt.getTranxReceiptMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    /* for Cash and Bank Account  */
                    ledgerCommonPostings.callToPostings(total_amt, mReceipt.getLedgerMaster(), tranxType,
                            mReceipt.getLedgerMaster().getAssociateGroups(),
                            mReceipt.getTranxReceiptMaster().getFiscalYear(), mReceipt.getBranch(),
                            mReceipt.getCompany(), mReceipt.getTranxReceiptMaster().getTranscationDate(),
                            mReceipt.getTranxReceiptMaster().getId(),
                            mReceipt.getTranxReceiptMaster().getReceiptNo(),
                            "DR", true, "Receipt", "Insert");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            receiptLogger.error("Error in insertIntoPostings :->" + e.getMessage());
        }
    }

    public JsonObject deleteReceipt(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject jsonObject = new JsonObject();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            TranxReceiptMaster receiptMaster = repository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
            receiptMaster.setStatus(false);
            repository.save(receiptMaster);
            if (receiptMaster != null) {
                List<TranxReceiptPerticulars> tranxReceiptPerticulars = tranxReceiptPerticularsRepository.
                        findByTranxReceiptMasterIdAndStatus(receiptMaster.getId(), true);
                for (TranxReceiptPerticulars mDetail : tranxReceiptPerticulars) {
                    if (mDetail.getType().equalsIgnoreCase("CR"))
                        insertIntoPostings(mDetail, mDetail.getCr(), "DR", "Delete");// Accounting Postings
                    else
                        insertIntoPostings(mDetail, mDetail.getDr(), "CR", "Delete");// Accounting Postings
                }
                jsonObject.addProperty("message", "Receipt invoice deleted successfully");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                jsonObject.addProperty("message", "error in receipt invoice deletion");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            receiptLogger.error("Error in receipt invoice Delete()->" + e.getMessage());
        }
        return jsonObject;
    }

    public Object checkInvoiceDateIsBetweenFY(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        try {
            LocalDate invoiceDate = LocalDate.parse(request.getParameter("invoiceDate"));
            FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(invoiceDate);
            if (fiscalYear == null) {
                response.addProperty("response", false);
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            } else {
                response.addProperty("response", true);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            response.addProperty("response", false);
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
}
