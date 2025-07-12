package com.opethic.hrms.HRMSNew.services.tranx_service.payment;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.opethic.hrms.HRMSNew.common.GenerateDates;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.common.GenerateSlugs;
import com.opethic.hrms.HRMSNew.common.LedgerCommonPostings;
import com.opethic.hrms.HRMSNew.dto.GenericDTData;
import com.opethic.hrms.HRMSNew.dto.PaymentMasterDTDTO;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.models.report.DayBook;
import com.opethic.hrms.HRMSNew.models.tranx.payment.TranxPaymentMaster;
import com.opethic.hrms.HRMSNew.models.tranx.payment.TranxPaymentPerticulars;
import com.opethic.hrms.HRMSNew.models.tranx.payment.TranxPaymentPerticularsDetails;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerBalanceSummaryRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionPostingsRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeePayrollRepository;
import com.opethic.hrms.HRMSNew.repositories.master.TransactionStatusRepository;
import com.opethic.hrms.HRMSNew.repositories.master.TransactionTypeMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.report_repository.DaybookRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.payment_repository.TranxPaymentMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.payment_repository.TranxPaymentPerticularsDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.payment_repository.TranxPaymentPerticularsRepository;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
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
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service

public class TranxPaymentNewService {

    @Autowired
    private JwtTokenUtil jwtRequestFilter;
//    @Autowired
//    private TranxPurInvoiceRepository tranxPurInvoiceRepository;
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    private LedgerBalanceSummaryRepository ledgerBalanceSummaryRepository;
    @Autowired
    private GenerateSlugs generateSlugs;
    @Autowired
    private TransactionTypeMasterRepository tranxRepository;
    @Autowired
    private LedgerTransactionDetailsRepository transactionDetailsRepository;
    @Autowired
    private GenerateFiscalYear generateFiscalYear;
//    @Autowired
//    private TranxDebitNoteNewReferenceRepository tranxDebitNoteNewReferenceRepository;

    @Autowired
    private TranxPaymentMasterRepository tranxPaymentMasterRepository;

    @Autowired
    private TranxPaymentPerticularsRepository tranxPaymentPerticularsRepository;

    @Autowired
    private TranxPaymentPerticularsDetailsRepository tranxPaymentPerticularsDetailsRepository;
    @Autowired
    private TransactionStatusRepository transactionStatusRepository;

//    @Autowired
//    private TranxCreditNoteNewReferenceRepository tranxCreditNoteNewReferenceRepository;

    @Autowired
    private DaybookRepository daybookRepository;
    @Autowired
    private LedgerCommonPostings ledgerCommonPostings;

    @Autowired
    private LedgerTransactionPostingsRepository ledgerTransactionPostingsRepository;

    @PersistenceContext
    private EntityManager entityManager;

    private static final Logger paymentLogger = LogManager.getLogger(TranxPaymentNewService.class);
    @Autowired
    private EmployeePayrollRepository employeePayrollRepository;

    public JsonObject paymentLastRecord(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Long count = 0L;
        if (users.getBranch() != null) {
            count = tranxPaymentMasterRepository.findBranchLastRecord(users.getCompany().getId(), users.getBranch().getId());
        } else {
            count = tranxPaymentMasterRepository.findLastRecord(users.getCompany().getId());
        }

        String serailNo = String.format("%05d", count + 1);// 5 digit serial number
        //first 3 digits of Current month
        GenerateDates generateDates = new GenerateDates();
        String currentMonth = generateDates.getCurrentMonth().substring(0, 3);
        String paymentCode = "PAYNT" + currentMonth + serailNo;
        JsonObject result = new JsonObject();
        result.addProperty("message", "success");
        result.addProperty("responseStatus", HttpStatus.OK.value());
        result.addProperty("payment_sr_no", count + 1);
        result.addProperty("payment_code", paymentCode);
        return result;
    }

    public JsonObject getSundryCreditorAndIndirectExpenses(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));

        JsonArray result = new JsonArray();
        JsonObject finalResult = new JsonObject();
        List<LedgerMaster> sundryCreditors = new ArrayList<>();
        List<LedgerMaster> sundryDebtors = new ArrayList<>();
        if (users.getBranch() != null) {

            sundryCreditors = ledgerMasterRepository.findByCompanyIdAndBranchIdAndPrincipleGroupsIdAndStatus(
                    users.getCompany().getId(), users.getBranch().getId(), 5L, true);
            sundryDebtors = ledgerMasterRepository.findByCompanyIdAndBranchIdAndPrincipleGroupsIdAndStatus(
                    users.getCompany().getId(), users.getBranch().getId(), 1L, true);

        } else {
            sundryCreditors = ledgerMasterRepository.findByCompanyIdAndPrincipleGroupsIdAndStatusAndBranchIsNull(users.getCompany().getId(), 5L, true);
            sundryDebtors = ledgerMasterRepository.findByCompanyIdAndPrincipleGroupsIdAndStatusAndBranchIsNull(users.getCompany().getId(), 1L, true);
        }
        /* for Sundry Creditors List */
        if (sundryCreditors.size() > 0) {
            for (LedgerMaster mLedger : sundryCreditors) {
                JsonObject response = new JsonObject();
                response.addProperty("id", mLedger.getId());
                response.addProperty("ledger_name", mLedger.getLedgerName());
                response.addProperty("balancing_method", mLedger.getBalancingMethod() != null ? generateSlugs.getSlug(mLedger.getBalancingMethod().getBalancingMethod()) : "");
                response.addProperty("type", "SC");
               /* LedgerBalanceSummary balanceSummary = ledgerBalanceSummaryRepository.findByLedgerMasterId(mLedger.getId());
                response.addProperty("balance", balanceSummary.getClosingBal());
                if (balanceSummary.getClosingBal() > 0) response.addProperty("balance_typ", "CR");
                else response.addProperty("balance_typ", "DR");*/
                result.add(response);
            }
        }  /* end of Sundry Creditors List */

        /* for Sundry debtor List*/
        if (sundryDebtors.size() > 0) {
            for (LedgerMaster mLedger : sundryDebtors) {
                JsonObject response = new JsonObject();
                response.addProperty("id", mLedger.getId());
                response.addProperty("ledger_name", mLedger.getLedgerName());
                response.addProperty("balancing_method", mLedger.getBalancingMethod() != null ? generateSlugs.getSlug(mLedger.getBalancingMethod().getBalancingMethod()) : "");
                response.addProperty("type", "SD");
              /*  LedgerBalanceSummary balanceSummary = ledgerBalanceSummaryRepository.findByLedgerMasterId(mLedger.getId());
                response.addProperty("balance", balanceSummary.getClosingBal());
                if (balanceSummary.getClosingBal() > 0) response.addProperty("balance_typ", "DR");
                else response.addProperty("balance_typ", "CR");*/
                result.add(response);
            }
        } /* end of Indirect Expenses List*/
        List<LedgerMaster> indirectExpenses = new ArrayList<>();
        indirectExpenses = ledgerMasterRepository.findByCompanyIdAndPrinciplesIdAndStatus(users.getCompany().getId(), 12L, true);
        if (indirectExpenses.size() > 0) {
            for (LedgerMaster mLedger : indirectExpenses) {
                if (!mLedger.getLedgerName().equalsIgnoreCase("Round Off") && !mLedger.getLedgerName().equalsIgnoreCase("Sales Discount")) {
                    JsonObject response = new JsonObject();
                    response.addProperty("id", mLedger.getId());
                    response.addProperty("ledger_name", mLedger.getLedgerName());
                    response.addProperty("balancing_method", "NA");
                    response.addProperty("type", "IE");
                    result.add(response);
                }
            }
        }
        /**** Current Assets *****/
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


    public JsonObject getCashAcBankAccountDetails(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        List<LedgerMaster> ledgerMaster = new ArrayList<>();
        if (users.getBranch() != null) {
            ledgerMaster = ledgerMasterRepository.findBranchBankAccountCashAccount(users.getCompany().getId(), users.getBranch().getId());
        } else {

            ledgerMaster = ledgerMasterRepository.findBankAccountCashAccount(users.getCompany().getId());
        }
        JsonObject response = new JsonObject();
        for (LedgerMaster mLedger : ledgerMaster) {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("id", mLedger.getId());
            jsonObject.addProperty("name", mLedger.getLedgerName());
            jsonObject.addProperty("type", mLedger.getSlugName());
            result.add(jsonObject);
        }
        if (result.size() > 0) {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("list", result);
        } else {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "empty list");
            response.add("list", result);
        }
        return response;
    }

    public JsonObject createPayments(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonObject response = new JsonObject();
        TranxPaymentMaster tranxPayment = new TranxPaymentMaster();
        Branch branch = null;
        if (users.getBranch() != null) {
            branch = users.getBranch();
            tranxPayment.setBranch(branch);
        }
        Company outlet = users.getCompany();
        tranxPayment.setCompany(outlet);
        tranxPayment.setStatus(true);
        tranxPayment.setCreatedBy(users.getId());
        LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
        tranxPayment.setTranscationDate(tranxDate);
        /*     fiscal year mapping  */
        FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
        if (fiscalYear != null) {
            tranxPayment.setFiscalYear(fiscalYear);
            tranxPayment.setFinancialYear(fiscalYear.getFiscalYear());
        }

        tranxPayment.setPaymentSrNo(Long.parseLong(request.getParameter("payment_sr_no")));
        if (paramMap.containsKey("narration")) tranxPayment.setNarrations(request.getParameter("narration"));
        else {
            tranxPayment.setNarrations(request.getParameter("NA"));
        }
        tranxPayment.setPaymentNo(request.getParameter("payment_code"));
        tranxPayment.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
        tranxPayment.setCreatedBy(users.getId());
        TranxPaymentMaster tranxPaymentMaster = tranxPaymentMasterRepository.save(tranxPayment);
        try {
            double total_amt = 0.0;
            String jsonStr = request.getParameter("row");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                String crdrType = "";
                /*Payment Master */
                JsonObject paymentRow = row.get(i).getAsJsonObject();
                /*Payment Perticulars */
                TranxPaymentPerticulars tranxPaymentPerticulars = new TranxPaymentPerticulars();
                LedgerMaster ledgerMaster = null;
                tranxPaymentPerticulars.setBranch(branch);
                tranxPaymentPerticulars.setCompany(outlet);
                tranxPaymentPerticulars.setStatus(true);
                ledgerMaster = ledgerMasterRepository.findByIdAndStatus(paymentRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                if (ledgerMaster != null) tranxPaymentPerticulars.setLedgerMaster(ledgerMaster);
                tranxPaymentPerticulars.setTranxPaymentMaster(tranxPaymentMaster);
                tranxPaymentPerticulars.setType(paymentRow.get("type").getAsJsonObject().get("type").getAsString());
                tranxPaymentPerticulars.setLedgerType(paymentRow.get("perticulars").getAsJsonObject().get("type").getAsString());
                tranxPaymentPerticulars.setLedgerName(paymentRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());
                crdrType = paymentRow.get("type").getAsJsonObject().get("type").getAsString();
                if (crdrType.equalsIgnoreCase("dr")) {
                    tranxPaymentPerticulars.setDr(paymentRow.get("paid_amt").getAsDouble());
                }
                if (crdrType.equalsIgnoreCase("cr")) {
                    tranxPaymentPerticulars.setCr(paymentRow.get("paid_amt").getAsDouble());
                }
                if (paymentRow.has("bank_payment_no")) {
                    tranxPaymentPerticulars.setPaymentTranxNo(paymentRow.get("bank_payment_no").getAsString());
                }
                if (paymentRow.has("bank_payment_type")) {
                    tranxPaymentPerticulars.setPaymentMethod(paymentRow.get("bank_payment_type").getAsString());
                }
                tranxPaymentPerticulars.setCreatedBy(users.getId());
                tranxPaymentPerticulars.setTransactionDate(tranxDate);
                TranxPaymentPerticulars mParticular = tranxPaymentPerticularsRepository.save(tranxPaymentPerticulars);
                total_amt = paymentRow.get("paid_amt").getAsDouble();

                /*Payment Perticulars Details*/
                JsonObject perticulars = paymentRow.get("perticulars").getAsJsonObject();
                JsonArray billList = new JsonArray();
                if (perticulars.has("billids")) {
                    billList = perticulars.get("billids").getAsJsonArray();
                    if (billList != null && billList.size() > 0) {
                        for (int j = 0; j < billList.size(); j++) {
                            TranxPaymentPerticularsDetails tranxPymtDetails = new TranxPaymentPerticularsDetails();
                            JsonObject jsonBill = billList.get(j).getAsJsonObject();
//                            TranxPurInvoice mPurInvoice = null;
                            tranxPymtDetails.setBranch(branch);
                            tranxPymtDetails.setCompany(outlet);
                            tranxPymtDetails.setStatus(true);
                            if (ledgerMaster != null) tranxPymtDetails.setLedgerMaster(ledgerMaster);
                            tranxPymtDetails.setTranxPaymentMaster(tranxPaymentMaster);
                            tranxPymtDetails.setTranxPaymentPerticulars(mParticular);
                            tranxPymtDetails.setStatus(true);
                            tranxPymtDetails.setCreatedBy(users.getId());
                            tranxPymtDetails.setTranxInvoiceId(jsonBill.get("invoice_id").getAsLong());
                            tranxPymtDetails.setType(jsonBill.get("source").getAsString());
                            tranxPymtDetails.setTotalAmt(jsonBill.get("amount").getAsDouble());
                            tranxPymtDetails.setPaidAmt(jsonBill.get("paid_amt").getAsDouble());
                            tranxPymtDetails.setTransactionDate(LocalDate.parse(jsonBill.get("invoice_date").getAsString()));
                            tranxPymtDetails.setTranxNo(jsonBill.get("invoice_no").getAsString());
                            tranxPaymentPerticularsDetailsRepository.save(tranxPymtDetails);

                        }
                    }
                }
                TranxPaymentPerticulars mPayment = tranxPaymentPerticularsRepository.save(tranxPaymentPerticulars);
                
                insertIntoPostings(mPayment, total_amt, crdrType.toUpperCase(), "Insert");//Accounting Postings
                Double closingBalance = 0.0;
                Double sumCR = 0.0;
                Double sumDR = 0.0;
                DecimalFormat df = new DecimalFormat("0.00");
                try {
                    Double openingBalance = ledgerMasterRepository.findOpeningBalance(ledgerMaster.getId());
                    sumCR = ledgerTransactionPostingsRepository.findsumCRForGivenMonth(ledgerMaster.getId(), String.valueOf(tranxDate.getMonthValue()), String.valueOf(tranxDate.getYear()));//-0.20
                    sumDR = ledgerTransactionPostingsRepository.findsumDRForGivenMonth(ledgerMaster.getId(), String.valueOf(tranxDate.getMonthValue()), String.valueOf(tranxDate.getYear()));//-0.40
                    closingBalance = openingBalance - sumDR + sumCR;//0-(-0.40)-0.20
                    System.out.println("closing balance"+closingBalance+" ledger : "+ledgerMaster.getLedgerName());
                    if (ledgerMaster.getFoundations().getId() == 2) {
//                        if (closingBalance < 0) {
//                            String yearMonth = null;
//                            String monthValue = null;
//                            String yearValue = null;
//                            yearValue = String.valueOf(tranxDate.getYear());
//                            monthValue = String.valueOf(tranxDate.getMonthValue());
//                            yearMonth = yearValue+"-"+monthValue;
//                            EmployeePayroll employeePayroll = null;
//                            employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(ledgerMaster.getEmployee().getId(), yearMonth);
////                                jsonObject.addProperty("dr", df.format(Math.abs(closingBalance)));
//                            if (employeePayroll != null) {
//                                employeePayroll.setYearMonth(yearMonth);
//                                employeePayroll.setAdvance(Math.abs(closingBalance));
//                            } else {
//                                employeePayroll = new EmployeePayroll();
//                                employeePayroll.setEmployee(ledgerMaster.getEmployee());
//                                employeePayroll.setYearMonth(yearMonth);
//                                employeePayroll.setAdvance(Math.abs(closingBalance));
//                            }
//                            EmployeePayroll obj = employeePayrollRepository.save(employeePayroll);
//                            if(obj != null){
//                                System.out.println("employee payroll updated");
//                            }
//                        }
                    }
                } catch (Exception e) {
                        e.printStackTrace();
                }
            }
            response.addProperty("message", "Payment successfully done..");
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            paymentLogger.error("Error in createPayments :->" + e.getMessage());
            response.addProperty("message", "Error in Payment creation");
            response.addProperty("responseStatus", HttpStatus.CONFLICT.value());
        }
        return response;
    }

    /* Accounting Postings of Payment Vouchers  */
    private void insertIntoPostings(TranxPaymentPerticulars paymentRows, double total_amt, String crdrType, String operation) {
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("PMT");
        try {
            /**** New Postings Logic *****/
            ledgerCommonPostings.callToPostings(total_amt, paymentRows.getLedgerMaster(), tranxType, paymentRows.getLedgerMaster().getAssociateGroups(), paymentRows.getTranxPaymentMaster().getFiscalYear(), paymentRows.getBranch(), paymentRows.getCompany(), paymentRows.getTranxPaymentMaster().getTranscationDate(), paymentRows.getTranxPaymentMaster().getId(), paymentRows.getTranxPaymentMaster().getPaymentNo(), crdrType, true, "Payment", operation);
            /**** Save into Day Book ****/
            if (crdrType.equalsIgnoreCase("dr") && operation.equalsIgnoreCase("Insert")) {
                saveIntoDayBook(paymentRows);
            }
        } catch (Exception e) {
            e.printStackTrace();
            paymentLogger.error("Error in insert into payment postings :->" + e.getMessage());
        }
    }

    private void saveIntoDayBook(TranxPaymentPerticulars paymentRows) {
        DayBook dayBook = new DayBook();
        dayBook.setCompany(paymentRows.getCompany());
        if (paymentRows.getBranch() != null) dayBook.setBranch(paymentRows.getBranch());
        dayBook.setAmount(paymentRows.getDr());
        dayBook.setTranxDate(paymentRows.getTranxPaymentMaster().getTranscationDate());
        dayBook.setParticulars(paymentRows.getLedgerMaster().getLedgerName());
        dayBook.setVoucherNo(paymentRows.getTranxPaymentMaster().getPaymentNo());
        dayBook.setVoucherType("Payment");
        dayBook.setStatus(true);
        daybookRepository.save(dayBook);
    }

//    public JsonObject getCreditorsPendingBillsNew(HttpServletRequest request) {
//
//        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//        Long ledgerId = Long.parseLong(request.getParameter("ledger_id"));
//        String type = request.getParameter("type");
////        List<TranxPurInvoice> mInput = new ArrayList<>();
////        List<TranxPurInvoice> purInvoice = new ArrayList<>();
////        List<TranxDebitNoteNewReferenceMaster> list = new ArrayList<>();
////        List<TranxCreditNoteNewReferenceMaster> listcrd = new ArrayList<>();
//        JsonArray result = new JsonArray();
//        JsonObject finalResult = new JsonObject();
//        try {
//            /* start of SC of bill by bill */
//            if (type.equalsIgnoreCase("SC")) {
//                LedgerMaster ledgerMaster = ledgerMasterRepository.findByIdAndStatus(ledgerId, true);
//                /* checking for Bill by bill (bill by bill id: 1) */
//                if (ledgerMaster.getBalancingMethod().getId() == 1) {
//                    /* find all purchase invoices against sundry creditor */
////                    if (users.getBranch()() != null) {
////                        purInvoice = tranxPurInvoiceRepository.findPendingBillsByBranch(users.getCompany().getId(), users.getBranch()().getId(), true, ledgerId);
////                    } else {
////                        purInvoice = tranxPurInvoiceRepository.findPendingBills(users.getCompany().getId(), true, ledgerId);
////                    }
////                    if (purInvoice.size() > 0) {
////                        for (TranxPurInvoice newPurInvoice : purInvoice) {
////                            JsonObject response = new JsonObject();
////                            response.addProperty("invoice_id", newPurInvoice.getId());
////                            response.addProperty("amount", newPurInvoice.getBalance());
////                            response.addProperty("total_amt", newPurInvoice.getTotalAmount());
////                            response.addProperty("invoice_date", newPurInvoice.getInvoiceDate().toString());
////                            response.addProperty("invoice_no", newPurInvoice.getVendorInvoiceNo());
////                            response.addProperty("ledger_id", ledgerId);
////                            response.addProperty("source", "pur_invoice");
////                            result.add(response);
////                        }
////                    }
//                } else {
//                    /*  supplier :  on Account  */
//                    // LedgerBalanceSummary mBalanceSummary = ledgerBalanceSummaryRepository.findByLedgerMasterId(ledgerId);
//                    // Double openingBalance = ledgerMasterRepository.findOpeningBalance(balanceSummary.getId());
//                    Double sumCR = 0.0;
//                    Double sumDR = 0.0, closingBalance = 0.0;
//                    sumCR = ledgerTransactionPostingsRepository.findsumCR(ledgerId);
//                    sumDR = ledgerTransactionPostingsRepository.findsumDR(ledgerId);
//                    closingBalance = sumCR - sumDR;//0-(-0.40)-0.20
//                    if (closingBalance != 0) {
//                        JsonObject response = new JsonObject();
//                        response.addProperty("amount", closingBalance);
//                        response.addProperty("ledger_id", ledgerId);
//                        result.add(response);
//                    }
//                }
////                list = tranxDebitNoteNewReferenceRepository.findBySundryCreditorIdAndStatusAndTransactionStatusIdAndAdjustmentStatusAndCompanyId(ledgerId, true, 1L, "credit", users.getCompany().getId());
////                if (list != null && list.size() > 0) {
////                    for (TranxDebitNoteNewReferenceMaster mTranxDebitNote : list) {
////                        if (mTranxDebitNote.getBalance() != 0.0) {
////                            JsonObject data = new JsonObject();
////                            data.addProperty("debit_note_id", mTranxDebitNote.getId());
////                            data.addProperty("debit_note_no", mTranxDebitNote.getDebitnoteNewReferenceNo());
////                            data.addProperty("debit_note_date", mTranxDebitNote.getCreatedAt().toString());
////                            data.addProperty("Total_amt", mTranxDebitNote.getBalance());
////                            data.addProperty("source", "debit_note");
////                            result.add(data);
////                        }
////                    }
////                }
//            }
//
//            if (type.equalsIgnoreCase("SD")) {
////                listcrd = tranxCreditNoteNewReferenceRepository.findBySundryDebtorsIdAndStatusAndTransactionStatusIdAndAdjustmentStatusAndCompanyId(ledgerId, true, 1L, "refund", users.getCompany().getId());
////                if (listcrd != null && listcrd.size() > 0) {
////                    for (TranxCreditNoteNewReferenceMaster mTranxCreditNote : listcrd) {
////                        if (mTranxCreditNote.getBalance() != 0.0) {
////                            JsonObject data = new JsonObject();
////                            data.addProperty("credit_note_id", mTranxCreditNote.getId());
////                            data.addProperty("credit_note_no", mTranxCreditNote.getCreditnoteNewReferenceNo());
////                            data.addProperty("credit_note_date", mTranxCreditNote.getCreatedAt().toString());
////                            data.addProperty("Total_amt", mTranxCreditNote.getBalance());
////                            data.addProperty("source", "credit_note");
////                            result.add(data);
////                        }
////                    }
////                }
//            }
//            if (type.equalsIgnoreCase("CA")) {
//                Double sumCR = 0.0;
//                Double sumDR = 0.0, closingBalance = 0.0;
//                sumCR = ledgerTransactionPostingsRepository.findsumCR(ledgerId);
//                sumDR = ledgerTransactionPostingsRepository.findsumDR(ledgerId);
//                closingBalance = sumCR - sumDR;//0-(-0.40)-0.20
//                if (closingBalance != 0) {
//                    JsonObject response = new JsonObject();
//                    response.addProperty("amount", Math.abs(closingBalance));
//                    response.addProperty("ledger_id", ledgerId);
//                    result.add(response);
//                }
//            }
//
//        } catch (Exception e) {
//            paymentLogger.error("Exception in: getCreditorsPendingBillsNew ->" + e.getMessage());
//            System.out.println("Exception in: get_creditors_pending_bills ->" + e.getMessage());
//            e.printStackTrace();
//        }
//        finalResult.addProperty("message", "success");
//        finalResult.addProperty("responseStatus", HttpStatus.OK.value());
//        finalResult.add("list", result);
//        return finalResult;
//    }

    public JsonObject paymentListbyCompany(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<TranxPaymentMaster> payment = new ArrayList<>();
        if (users.getBranch() != null) {
            payment = tranxPaymentMasterRepository.findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch().getId(), true);
        } else {
            payment = tranxPaymentMasterRepository.findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
        }

        for (TranxPaymentMaster invoices : payment) {
            JsonObject response = new JsonObject();
            response.addProperty("id", invoices.getId());
            response.addProperty("payment_code", invoices.getPaymentNo());
            response.addProperty("transaction_dt", invoices.getTranscationDate().toString());
            response.addProperty("payment_sr_no", invoices.getPaymentSrNo());
            List<TranxPaymentPerticulars> tranxPaymentPerticulars = tranxPaymentPerticularsRepository.findLedgerName(invoices.getId(), users.getCompany().getId(), true);
            response.addProperty("total_amount", invoices.getTotalAmt());
            response.addProperty("ledger_name", tranxPaymentPerticulars != null &&
                    tranxPaymentPerticulars.size() > 0 ? tranxPaymentPerticulars.get(0).getLedgerName() : "");
            response.addProperty("narration", invoices.getNarrations());
            result.add(response);
        }

        JsonObject output = new JsonObject();
        output.addProperty("message", "success");
        output.addProperty("responseStatus", HttpStatus.OK.value());
        output.add("data", result);
        return output;
    }

    public JsonObject getPaymentById(HttpServletRequest request) {

        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<TranxPaymentPerticulars> list = new ArrayList<>();
        JsonArray units = new JsonArray();
        List<TranxPaymentPerticularsDetails> detailsList = new ArrayList<>();
        JsonObject finalResult = new JsonObject();
        try {
            Long paymentId = Long.parseLong(request.getParameter("payment_id"));
            TranxPaymentMaster tranxPaymentMaster = tranxPaymentMasterRepository.findByIdAndCompanyIdAndStatus(paymentId, users.getCompany().getId(), true);

            list = tranxPaymentPerticularsRepository.findByTranxPaymentMasterIdAndStatus(tranxPaymentMaster.getId(), true);
            detailsList = tranxPaymentPerticularsDetailsRepository.findByIdAndStatus(tranxPaymentMaster.getId(), true);
            finalResult.addProperty("payment_no", tranxPaymentMaster.getPaymentNo());
            finalResult.addProperty("payment_sr_no", tranxPaymentMaster.getPaymentSrNo());
            finalResult.addProperty("tranx_date", tranxPaymentMaster.getTranscationDate().toString());
            finalResult.addProperty("total_amt", tranxPaymentMaster.getTotalAmt());
            finalResult.addProperty("narrations", tranxPaymentMaster.getNarrations());

            JsonArray row = new JsonArray();
            if (list.size() > 0) {
                for (TranxPaymentPerticulars mdetails : list) {
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
                    row.add(rpdetails);
                }
            }
            JsonArray rowDetails = new JsonArray();
            if (detailsList.size() > 0) {
                for (TranxPaymentPerticularsDetails mdetails : detailsList) {
                    JsonObject rpddetails = new JsonObject();
                    rpddetails.addProperty("tranxInvoiceId", mdetails.getTranxInvoiceId());
                    rpddetails.addProperty("type", mdetails.getType());
                    rpddetails.addProperty("paid_amount", mdetails.getPaidAmt());
                    rpddetails.addProperty("tranx_date", mdetails.getTransactionDate().toString());
                    rpddetails.addProperty("tranx_no", mdetails.getTranxNo());
                    rpddetails.addProperty("total_amt", mdetails.getTotalAmt());
                    rowDetails.add(rpddetails);

                }
            }
            finalResult.addProperty("message", "success");
            finalResult.addProperty("responseStatus", HttpStatus.OK.value());
            finalResult.add("payment_peritculars", row);
            finalResult.add("payment_perticulars_details", rowDetails);

        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            paymentLogger.error("Error in getPaymentById" + e.getMessage());
            System.out.println(e.getMessage());
            e.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.CONFLICT.value());
        } catch (Exception e1) {
            e1.printStackTrace();
            paymentLogger.error("Error in getPaymentById" + e1.getMessage());
            System.out.println(e1.getMessage());
            e1.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return finalResult;
    }

    public JsonObject upadatePayments(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        TranxPaymentMaster tranxPayment = tranxPaymentMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("payment_id")), true);
        JsonObject response = new JsonObject();
//        TranxPaymentMaster tranxPayment = new TranxPaymentMaster();
        Branch branch = null;
        if (users.getBranch() != null) {
            branch = users.getBranch();
            tranxPayment.setBranch(branch);
        }
        Company outlet = users.getCompany();
        tranxPayment.setCompany(outlet);
        //tranxPayment.setStatus(true);
        tranxPayment.setCreatedBy(users.getId());
        //tranxPayment.setupdatedBy(users.getId());
        LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
        tranxPayment.setTranscationDate(tranxDate);
        /*     fiscal year mapping  */
        FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
        if (fiscalYear != null) {
            tranxPayment.setFiscalYear(fiscalYear);
            tranxPayment.setFinancialYear(fiscalYear.getFiscalYear());
        }

        tranxPayment.setPaymentSrNo(Long.parseLong(request.getParameter("payment_sr_no")));
        if (paramMap.containsKey("narration")) tranxPayment.setNarrations(request.getParameter("narration"));
        else {
            tranxPayment.setNarrations(request.getParameter("NA"));
        }
        tranxPayment.setPaymentNo(request.getParameter("payment_code"));
        tranxPayment.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
        TranxPaymentMaster tranxPaymentMaster = tranxPaymentMasterRepository.save(tranxPayment);
        try {
            double total_amt = 0.0;
            String jsonStr = request.getParameter("row");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                /*Receipt Master */

                JsonObject paymentRow = row.get(i).getAsJsonObject();

                /*Payment Perticulars */


                TranxPaymentPerticulars tranxPaymentPerticulars = null;
                Long detailsId = 0L;
                if (paymentRow.has("details_id")) detailsId = paymentRow.get("details_id").getAsLong();
                if (detailsId != 0) {
                    tranxPaymentPerticulars = tranxPaymentPerticularsRepository.findByIdAndStatus(detailsId, true);
                } else {
                    tranxPaymentPerticulars = new TranxPaymentPerticulars();
                    tranxPaymentPerticulars.setStatus(true);
                }
//                TranxPaymentPerticulars tranxPaymentPerticulars = new TranxPaymentPerticulars();
                LedgerMaster ledgerMaster = null;
                tranxPaymentPerticulars.setBranch(branch);
                tranxPaymentPerticulars.setCompany(outlet);
                ledgerMaster = ledgerMasterRepository.findByIdAndStatus(paymentRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                if (ledgerMaster != null) tranxPaymentPerticulars.setLedgerMaster(ledgerMaster);
                tranxPaymentPerticulars.setTranxPaymentMaster(tranxPaymentMaster);
                tranxPaymentPerticulars.setType(paymentRow.get("type").getAsJsonObject().get("type").getAsString());
                tranxPaymentPerticulars.setLedgerType(paymentRow.get("perticulars").getAsJsonObject().get("type").getAsString());
                tranxPaymentPerticulars.setLedgerName(paymentRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());
                if (paymentRow.get("type").getAsJsonObject().get("type").getAsString().equalsIgnoreCase("dr")) {
                    tranxPaymentPerticulars.setDr(paymentRow.get("paid_amt").getAsDouble());
                }
                if (paymentRow.get("type").getAsJsonObject().get("type").getAsString().equalsIgnoreCase("cr")) {
                    tranxPaymentPerticulars.setCr(paymentRow.get("paid_amt").getAsDouble());
                }
                if (paymentRow.has("bank_payment_no")) {
                    tranxPaymentPerticulars.setPaymentTranxNo(paymentRow.get("bank_payment_no").getAsString());
                }
                if (paymentRow.has("bank_payment_type")) {
                    tranxPaymentPerticulars.setPaymentMethod(paymentRow.get("bank_payment_type").getAsString());
                }
                tranxPaymentPerticulars.setCreatedBy(users.getId());
                //tranxPaymentPerticulars.setUpdatedBy(users.getId());

                TranxPaymentPerticulars mParticular = tranxPaymentPerticularsRepository.save(tranxPaymentPerticulars);
                total_amt = paymentRow.get("paid_amt").getAsDouble();

                /*Receipt Perticulars Details*/

                JsonObject perticulars = paymentRow.get("perticulars").getAsJsonObject();
                JsonArray billList = new JsonArray();
                if (perticulars.has("billids")) {
                    billList = perticulars.get("billids").getAsJsonArray();
                    if (billList != null && billList.size() > 0) {
                        for (int j = 0; j < billList.size(); j++) {
                            TranxPaymentPerticularsDetails tranxPymtDetails = new TranxPaymentPerticularsDetails();
                            JsonObject jsonBill = billList.get(j).getAsJsonObject();
//                            TranxPurInvoice mPurInvoice = null;
                      /*      tranxPymtDetails.setBranch(branch);
                            tranxPymtDetails.setCompany(outlet);
                            tranxPymtDetails.setStatus(true);
                      */
                            if (ledgerMaster != null) tranxPymtDetails.setLedgerMaster(ledgerMaster);
                            tranxPymtDetails.setTranxPaymentMaster(tranxPaymentMaster);
                            tranxPymtDetails.setTranxPaymentPerticulars(mParticular);
                            //  tranxPymtDetails.setStatus(true);
                            //tranxPymtDetails.setCreatedBy(users.getId());
                            tranxPymtDetails.setTranxInvoiceId(jsonBill.get("invoice_id").getAsLong());
                            tranxPymtDetails.setType(jsonBill.get("source").getAsString());
                            tranxPymtDetails.setTotalAmt(jsonBill.get("amount").getAsDouble());
                            tranxPymtDetails.setPaidAmt(jsonBill.get("paid_amt").getAsDouble());
                            tranxPymtDetails.setTransactionDate(LocalDate.parse(jsonBill.get("invoice_date").getAsString()));
                            tranxPymtDetails.setTranxNo(jsonBill.get("invoice_no").getAsString());
//                            if (jsonBill.get("source").getAsString().equalsIgnoreCase("pur_invoice")) {
//
//                                mPurInvoice = tranxPurInvoiceRepository.findByIdAndStatus(jsonBill.get("invoice_id").getAsLong(), true);
//                                if (jsonBill.has("remaining_amt")) {
//                                    //tranxReceipt.setBalance(jsonBill.get("remaining_amt").getAsDouble());
//                                    mPurInvoice.setBalance(jsonBill.get("remaining_amt").getAsDouble());
//                                    tranxPurInvoiceRepository.save(mPurInvoice);
//                                }
//                            } else if (jsonBill.get("source").getAsString().equalsIgnoreCase("debit_note")) {
//                                TranxDebitNoteNewReferenceMaster tranxDebitNoteNewReference = tranxDebitNoteNewReferenceRepository.findByIdAndStatus(jsonBill.get("invoice_id").getAsLong(), true);
//
//                                if (jsonBill.has("remaining_amt")) {
//                                    //tranxReceipt.setBalance(jsonBill.get("remaining_amt").getAsDouble());
//                                    Double mbalance = jsonBill.get("remaining_amt").getAsDouble();
//                                    tranxDebitNoteNewReference.setBalance(mbalance);
//                                    if (mbalance == 0.0) {
//                                        TransactionStatus transactionStatus = transactionStatusRepository.findByStatusNameAndStatus("closed", true);
//                                        tranxDebitNoteNewReference.setTransactionStatus(transactionStatus);
//                                        tranxDebitNoteNewReferenceRepository.save(tranxDebitNoteNewReference);
//                                    }
//                                }
//                            } else if (jsonBill.get("source").getAsString().equalsIgnoreCase("credit_note")) {
//                                TranxCreditNoteNewReferenceMaster tranxCreditNoteNewReference = tranxCreditNoteNewReferenceRepository.findByIdAndStatus(jsonBill.get("invoice_id").getAsLong(), true);
//
//
//                                if (jsonBill.has("remaining_amt")) {
//                                    Double mbalance = jsonBill.get("remaining_amt").getAsDouble();
//                                    tranxCreditNoteNewReference.setBalance(mbalance);
//                                    if (mbalance == 0.0) {
//                                        TransactionStatus transactionStatus = transactionStatusRepository.findByStatusNameAndStatus("closed", true);
//                                        tranxCreditNoteNewReference.setTransactionStatus(transactionStatus);
//                                        tranxCreditNoteNewReferenceRepository.save(tranxCreditNoteNewReference);
//                                    }
//                                }
//                            }
                            // save into tranxRptDetails
                            tranxPaymentPerticularsDetailsRepository.save(tranxPymtDetails);
                        }
                    }
                }

                TranxPaymentPerticulars mPayment = tranxPaymentPerticularsRepository.save(tranxPaymentPerticulars);
                updateIntoPostings(mPayment, total_amt, detailsId);
            }


            response.addProperty("message", "Payment successfully done..");
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            paymentLogger.error("Error in createPayments :->" + e.getMessage());
            response.addProperty("message", "Error in Payment creation");
            response.addProperty("responseStatus", HttpStatus.OK.value());
        }
        return response;
    }

    private void updateIntoPostings(TranxPaymentPerticulars paymentRows, double total_amt, Long detailsId) {
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("PMT");
        try {
            /* for Sundry Creditors  */
            if (paymentRows.getType().equalsIgnoreCase("dr")) {
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(paymentRows.getLedgerMaster().getId(), tranxType.getId(), paymentRows.getTranxPaymentMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(paymentRows.getTranxPaymentMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    ledgerCommonPostings.callToPostings(total_amt, paymentRows.getLedgerMaster(), tranxType,
                            paymentRows.getLedgerMaster().getAssociateGroups(),
                            paymentRows.getTranxPaymentMaster().getFiscalYear(), paymentRows.getBranch(),
                            paymentRows.getCompany(), paymentRows.getTranxPaymentMaster().getTranscationDate(),
                            paymentRows.getTranxPaymentMaster().getId(),
                            paymentRows.getTranxPaymentMaster().getPaymentNo(),
                            "DR", true, "Payment", "Insert");
                }
            } else {
                /* for Cash and Bank Account  */
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(paymentRows.getLedgerMaster().getId(), tranxType.getId(), paymentRows.getTranxPaymentMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(paymentRows.getTranxPaymentMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    // transactionDetailsRepository.insertIntoLegerTranxDetailsPosting(paymentRows.getLedgerMaster().getFoundations().getId(), paymentRows.getLedgerMaster().getPrinciples() != null ? paymentRows.getLedgerMaster().getPrinciples().getId() : null, paymentRows.getLedgerMaster().getPrincipleGroups() != null ? paymentRows.getLedgerMaster().getPrincipleGroups().getId() : null, null, tranxType.getId(), paymentRows.getLedgerMaster().getBalancingMethod() != null ? paymentRows.getLedgerMaster().getBalancingMethod().getId() : null, paymentRows.getBranch()()() != null ? paymentRows.getBranch()()().getId() : null, paymentRows.getCompany()().getId(), "NA", 0.0, total_amt, paymentRows.getTranxPaymentMaster().getTranscationDate(), null, paymentRows.getId(), tranxType.getTransactionName(), paymentRows.getLedgerMaster().getUnderPrefix(), paymentRows.getTranxPaymentMaster().getFinancialYear(), paymentRows.getCreatedBy(), paymentRows.getLedgerMaster().getId(), paymentRows.getTranxPaymentMaster().getPaymentNo());
                    /**** New Postings Logic *****/
                    ledgerCommonPostings.callToPostings(total_amt, paymentRows.getLedgerMaster(),
                            tranxType, paymentRows.getLedgerMaster().getAssociateGroups(),
                            paymentRows.getTranxPaymentMaster().getFiscalYear(), paymentRows.getBranch(),
                            paymentRows.getCompany(), paymentRows.getTranxPaymentMaster().getTranscationDate(),
                            paymentRows.getTranxPaymentMaster().getId(),
                            paymentRows.getTranxPaymentMaster().getPaymentNo(),
                            "CR", true, "Payment", "Insert");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            paymentLogger.error("Error in insertIntoPostings :->" + e.getMessage());
        }
    }

    public JsonObject deletePayment(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject jsonObject = new JsonObject();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("PMT");
        try {
            System.out.println(requestParam.get("id"));
        TranxPaymentMaster paymentMaster = tranxPaymentMasterRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
//        TranxPaymentPerticularsDetails mParticular = tranxPaymentPerticularsDetailsRepository.
//                findByTranxPaymentMasterIdAndStatus(paymentMaster.getId(), true);

            paymentMaster.setStatus(false);
            tranxPaymentMasterRepository.save(paymentMaster);
            /**** setting balance reverse to Invoice Bill for Listing of Payment Invoice*****/
//            if (mParticular != null) {
//                TranxPurInvoice mInvoice = tranxPurInvoiceRepository.findByIdAndStatus(mParticular.getTranxInvoiceId(), true);
//                if (mInvoice != null) {
//                    mInvoice.setBalance(mParticular.getPaidAmt());
//                    try {
//                        tranxPurInvoiceRepository.save(mInvoice);
//                    } catch (Exception e) {
//                        paymentLogger.error("Exception in delete payment ->" + e.getMessage());
//                    }
//                }
//            }
            if (paymentMaster != null) {
                List<TranxPaymentPerticulars> tranxPaymentPerticulars = tranxPaymentPerticularsRepository.
                        findByTranxPaymentMasterIdAndStatus(paymentMaster.getId(), true);
                for (TranxPaymentPerticulars mDetail : tranxPaymentPerticulars) {
                    if (mDetail.getType().equalsIgnoreCase("CR"))
                        insertIntoPostings(mDetail, mDetail.getCr(), "DR", "Delete");// Accounting Postings
                    else
                        insertIntoPostings(mDetail, mDetail.getDr(), "CR", "Delete");// Accounting Postings
                }
                /**** make status=0 to all ledgers of respective Payment voucher id, due to this we wont get
                 details of deleted invoice when we want get details of respective ledger ****/
                List<LedgerTransactionPostings> mInoiceLedgers = new ArrayList<>();
                mInoiceLedgers = ledgerTransactionPostingsRepository.findByTransactionTypeIdAndTransactionIdAndStatus(tranxType.getId(), paymentMaster.getId(), true);
                for (LedgerTransactionPostings mPostings : mInoiceLedgers) {
                    try {
                        mPostings.setStatus(false);
                        ledgerTransactionPostingsRepository.save(mPostings);
                    } catch (Exception e) {
                        paymentLogger.error("Exception in Delete functionality for all ledgers of" + " deleted purchase invoice->" + e.getMessage());
                    }
                }
                TranxPaymentPerticulars perticulars = tranxPaymentPerticularsRepository.findByTranxPaymentMasterIdAndTypeAndStatus(paymentMaster.getId(),"dr", true);
                if(perticulars != null){
                    Double closingBalance = 0.0;
                    Double sumCR = 0.0;
                    Double sumDR = 0.0;
                    DecimalFormat df = new DecimalFormat("0.00");
                    try {
                        Double openingBalance = ledgerMasterRepository.findOpeningBalance(perticulars.getLedgerMaster().getId());
                        sumCR = ledgerTransactionPostingsRepository.findsumCRForGivenMonth(perticulars.getLedgerMaster().getId(), String.valueOf(perticulars.getTransactionDate().getMonthValue()), String.valueOf(perticulars.getTransactionDate().getYear()));//-0.20
                        sumDR = ledgerTransactionPostingsRepository.findsumDRForGivenMonth(mInoiceLedgers.get(0).getLedgerMaster().getId(), String.valueOf(perticulars.getTransactionDate().getMonthValue()), String.valueOf(perticulars.getTransactionDate().getYear()));//-0.40
                        closingBalance = openingBalance - sumDR + sumCR;//0-(-0.40)-0.20
                        System.out.println("closing balance"+closingBalance+" ledger : "+perticulars.getLedgerMaster().getLedgerName());
                        if (perticulars.getLedgerMaster().getFoundations().getId() == 2) {
                            if (closingBalance <= 0) {
                                String yearMonth = null;
                                String monthValue = null;
                                String yearValue = null;
                                yearValue = String.valueOf(perticulars.getTransactionDate().getYear());
                                monthValue = String.valueOf(perticulars.getTransactionDate().getMonthValue());
                                yearMonth = yearValue+"-"+monthValue;
                                EmployeePayroll employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(perticulars.getLedgerMaster().getEmployee().getId(), yearMonth);
                                if (employeePayroll != null) {
                                    employeePayroll.setYearMonth(yearMonth);
                                    employeePayroll.setAdvance(Math.abs(closingBalance));
                                }
                                EmployeePayroll obj = employeePayrollRepository.save(employeePayroll);
                                if(obj != null){
                                    System.out.println("employee payroll updated");
                                }
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                jsonObject.addProperty("message", "Payment invoice deleted successfully");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                jsonObject.addProperty("message", "error in payment invoice deletion");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            paymentLogger.error("Error in payment invoice Delete()->" + e.getMessage());
        }
        return jsonObject;
    }

    public Object DTPaymenttList(Map<String, String> request, HttpServletRequest httpServletRequest) {
        Integer from = Integer.parseInt(request.get("from"));
        Integer to = Integer.parseInt(request.get("to"));
        String searchText = request.get("searchText");
        Users users = jwtRequestFilter.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        GenericDTData genericDTData = new GenericDTData();
        List<TranxPaymentMaster> tranxPaymentMasterList = new ArrayList<>();
        List<PaymentMasterDTDTO> paymentMasterDTDTOList = new ArrayList<>();
        String query = "";
        try {
            if (users.getBranch() != null) {
//                receipt = repository.findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch()().getId(), true);
//                query = "SELECT * FROM `tranx_receipt_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND branch_id="+users.getBranch()().getId()+" " +
//                        "AND tranx_receipt_master_tbl.status=1";
                query="SELECT m.*, p.* FROM tranx_payment_master_tbl m LEFT JOIN tranx_payment_perticulars_tbl p "+
                        "ON m.id=p.tranx_payment_master_id WHERE p.company_id="+users.getCompany().getId()+" AND "+
                        "p.branch_id="+users.getBranch().getId()+" AND m.status=1 GROUP BY m.payment_no";
            } else {
//                receipt = repository.findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
//                query = "SELECT * FROM `tranx_receipt_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND tranx_receipt_master_tbl.status=1";
                query="SELECT m.*, p.* FROM tranx_payment_master_tbl m LEFT JOIN tranx_payment_perticulars_tbl p "+
                        "ON m.id=p.tranx_payment_master_id WHERE p.company_id="+users.getCompany().getId()+
                        " AND m.status=1 GROUP BY m.payment_no";
            }


            if (!searchText.equalsIgnoreCase("")) {
                query = query + " AND (payment_no LIKE '%" + searchText + "%' OR narration LIKE '%" +
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

            Query q = entityManager.createNativeQuery(query, TranxPaymentMaster.class);
            Query q1 = entityManager.createNativeQuery(query1, TranxPaymentMaster.class);

            tranxPaymentMasterList = q.getResultList();
            System.out.println("Limit total rows " + tranxPaymentMasterList);

            for (TranxPaymentMaster tranxPaymentMaster : tranxPaymentMasterList) {
                paymentMasterDTDTOList.add(convertToDTDTO(tranxPaymentMaster));
            }

            List<TranxPaymentMaster> tranxPaymentMasterArrayList = new ArrayList<>();
            tranxPaymentMasterArrayList = q1.getResultList();
            System.out.println("total rows " + tranxPaymentMasterList.size());

            genericDTData.setRows(paymentMasterDTDTOList);
            genericDTData.setTotalRows(tranxPaymentMasterList.size());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            genericDTData.setRows(paymentMasterDTDTOList);
            genericDTData.setTotalRows(0);
        }
        return genericDTData;
    }


    private PaymentMasterDTDTO convertToDTDTO(TranxPaymentMaster rMaster) {
        PaymentMasterDTDTO paymentMaster = new PaymentMasterDTDTO();
        paymentMaster.setId(rMaster.getId());
        paymentMaster.setPaymentNo(rMaster.getPaymentNo());
        paymentMaster.setPaymentSrNo(rMaster.getPaymentSrNo());
//        paymentMaster.setTranxReceiptPerticulars(rMaster.getTranxReceiptPerticulars().size() > 0 ? rMaster.getTranxReceiptPerticulars().get(0).getLedgerName() : "");
        paymentMaster.setTranscationDate(rMaster.getTranscationDate().toString());
        paymentMaster.setNarrations(rMaster.getNarrations());
        paymentMaster.setTotalAmt(rMaster.getTotalAmt());
        paymentMaster.setStatus(rMaster.getStatus());
        paymentMaster.setCreatedAt(String.valueOf(rMaster.getCreatedAt()));
        return paymentMaster;
    }

}
