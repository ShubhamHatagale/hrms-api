package com.opethic.hrms.HRMSNew.services.reports_service;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.common.LedgerCommonPostings;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import com.opethic.hrms.HRMSNew.models.master.FiscalYear;
import com.opethic.hrms.HRMSNew.models.master.LedgerMaster;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.models.tranx.contra.TranxContraDetails;
import com.opethic.hrms.HRMSNew.models.tranx.journal.TranxJournalDetails;
import com.opethic.hrms.HRMSNew.models.tranx.payment.TranxPaymentPerticularsDetails;
import com.opethic.hrms.HRMSNew.models.tranx.receipt.TranxReceiptPerticularsDetails;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionPostingsRepository;
import com.opethic.hrms.HRMSNew.repositories.master.FiscalYearRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.contra_repository.TranxContraDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.journal_repository.TranxJournalDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.payment_repository.TranxPaymentPerticularsDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.receipt_repository.TranxReceiptPerticularsDetailsRepository;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class LedgerReportService {

    @Autowired
    FiscalYearRepository fiscalYearRepository;
    @Autowired
    private JwtTokenUtil jwtRequestFilter;
    @Autowired
    LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    LedgerTransactionPostingsRepository transactionDetailsRepository;
//    @Autowired
//    TranxPurInvoiceRepository tranxPurInvoiceRepository;
//    @Autowired
//    TranxSalesInvoiceRepository tranxSalesInvoiceRepository;
//    @Autowired
//    TranxSalesReturnRepository tranxSalesReturnRepository;
    @Autowired
    TranxReceiptPerticularsDetailsRepository tranxReceiptPerticularsDetailsRepository;
//    @Autowired
//    TranxPurReturnsRepository tranxPurReturnsRepository;
    @Autowired
    TranxPaymentPerticularsDetailsRepository tranxPaymentPerticularsDetailsRepository;
    @Autowired
    TranxJournalDetailsRepository tranxJournalDetailsRepository;
    @Autowired
    TranxContraDetailsRepository tranxContraDetailsRepository;
//    @Autowired
//    TranxCreditNoteDetailsRepository tranxCreditNoteDetailsRepository;

//    @Autowired
//    LedgerTransactionPostingsRepository postingsRepository;
//    @Autowired
//    TranxDebitNoteDetailsRepository tranxDebitNoteDetailsRepository;

    @Autowired
    private GenerateFiscalYear generateFiscalYear;
    @Autowired
    private LedgerCommonPostings ledgerCommonPostings;

    public Object getLedgerTransactionsDetails(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        JsonObject finalResponse = new JsonObject();

        JsonArray response = new JsonArray();
        List<LedgerTransactionPostings> mlist = new ArrayList<>();
        Map<String, String[]> paramMap = request.getParameterMap();
        try {
            Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Long ledger_master_id = Long.valueOf(request.getParameter("id"));
            String startDate = "";
            String endDate = "";
            LocalDate endDatep = null;
            LocalDate startDatep = null;
            Long branchId = null;
            FiscalYear fiscalYear = null;
            Boolean flag = false;
            LedgerMaster ledgerMaster = ledgerMasterRepository.findByIdAndStatus(ledger_master_id, true);
//            if (users.getBranch() != null) {
//                branchId = users.getBranch().getId();
//            }
//            if (paramMap.containsKey("start_date") && paramMap.containsKey("end_date")) {
//                startDate = LocalDate.parse(request.getParameter("start_date"));
//                endDate = LocalDate.parse(request.getParameter("end_date"));
//                mlist = transactionDetailsRepository.findByDetailsBetweenDates(users.getOutlet().getId(), branchId, true, ledger_master_id, startDate, endDate);
//            } else {
//                startDate = LocalDate.now();
//                endDate = LocalDate.now();
//                mlist = transactionDetailsRepository.findByDetails(users.getOutlet().getId(), branchId, true, ledger_master_id);
//            }

            if (paramMap.containsKey("startDate") && paramMap.containsKey("endDate")) {
                startDate = request.getParameter("startDate");
                startDatep = LocalDate.parse(startDate);
                endDate = request.getParameter("endDate");
                endDatep = LocalDate.parse(endDate);
                flag = true;
            } else {
                List<Object[]> list = new ArrayList<>();
                fiscalYear = generateFiscalYear.getFiscalYear(LocalDate.now());
                flag = false;
            }
            if (flag == true) {
                if (users.getBranch() != null) {
                    mlist = transactionDetailsRepository.findByDetailsBetweenDates(users.getCompany().getId(), users.getBranch().getId(), true, ledger_master_id, startDatep, endDatep);

//                branchId = users.getBranch().getId();
                } else {
                    mlist = transactionDetailsRepository.findByDetails(users.getCompany().getId(), true, ledger_master_id, startDatep, endDatep);
                }
            } else {
                if (users.getBranch() != null) {
                    mlist = transactionDetailsRepository.findByDetailsBranch(users.getCompany().getId(), users.getBranch().getId(), true, ledger_master_id);

//                branchId = users.getBranch().getId();
                } else {
                    mlist = transactionDetailsRepository.findByDetailsFisc(users.getCompany().getId(), true, ledger_master_id);
                }
            }
            JsonArray innerArr = new JsonArray();
            innerArr = getCommonDetails(mlist, users);
//            res.addProperty("d_start_date", startDate.toString());
//            res.addProperty("d_end_date", endDate.toString());
            Double openingStock = 0.0;
            openingStock = ledgerCommonPostings.getOpeningStock(ledger_master_id,
                    users.getCompany().getId(), branchId, startDatep, endDatep, flag, fiscalYear);
//                mJsonObject.addProperty("invoice_id",ledger_master_id);
//                mJsonObject.addProperty("particulars",lposting.getLedgerMaster().getLedgerName());
//                mJsonObject.addProperty("quantity",mUnit.ge);
//                mJsonObject.addProperty("unit_name",lposting.getUnits().getUnitName());
            finalResponse.addProperty("crdrType", ledgerMaster.getOpeningBalType().toLowerCase());
            finalResponse.add("response", innerArr);
            finalResponse.addProperty("opening_stock", Math.abs(openingStock));
            //finalResponse.add("response", response);
            finalResponse.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            finalResponse.addProperty("message", "Failed To Load Data");
            finalResponse.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return finalResponse;
    }

    public Object getLedgerTransactionsDetailsWithDates(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        List<LedgerTransactionPostings> mlist = new ArrayList<>();
        Map<String, String[]> paramMap = request.getParameterMap();
        try {
            Users users = jwtRequestFilter.getUserDataFromToken(
                    request.getHeader("Authorization").substring(7));
            Long ledger_master_id = Long.valueOf(request.getParameter("id"));
            LocalDate startDate = null;
            LocalDate endDate = null;
            Long branchId = null;
            if (users.getBranch() != null) {
                branchId = users.getBranch().getId();
            }
            if (paramMap.containsKey("start_date") && paramMap.containsKey("end_date")) {
                startDate = LocalDate.parse(request.getParameter("start_date"));
                endDate = LocalDate.parse(request.getParameter("end_date"));
                mlist = transactionDetailsRepository.findByDetailsBetweenDates(users.getCompany().getId(), branchId, true, ledger_master_id, startDate, endDate);
            }
            JsonArray innerArr = new JsonArray();
            innerArr = getCommonDetails(mlist, users);
            res.addProperty("d_start_date", startDate.toString());
            res.addProperty("d_end_date", endDate.toString());
            res.add("response", innerArr);
            res.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            res.addProperty("message", "Failed To Load Data");
            res.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return res;
    }

    public JsonArray getCommonDetails(List<LedgerTransactionPostings> mlist, Users users) {
        JsonArray innerArr = new JsonArray();
        for (LedgerTransactionPostings ledgerTransactionDetails : mlist) {
            Double amt = 0.0;
            if (!ledgerTransactionDetails.getOperations().equalsIgnoreCase("Delete")) {
                JsonObject inside = new JsonObject();
                inside.addProperty("transaction_date", ledgerTransactionDetails.getTransactionDate().toString());
                inside.addProperty("invoice_no", ledgerTransactionDetails.getInvoiceNo());
                inside.addProperty("invoice_id", ledgerTransactionDetails.getTransactionId());// Invoice Id : 1 or 2
                Long tranx_type = ledgerTransactionDetails.getTransactionType().getId(); // Transactions Id : 1:Pur 3: Sales
                inside.addProperty("transaction_type", tranx_type);
                if (tranx_type == 5) {
                    TranxReceiptPerticularsDetails tranxReceiptPerticularsDetails;
                    if (users.getBranch() != null) {
                        tranxReceiptPerticularsDetails = tranxReceiptPerticularsDetailsRepository.findByIdAndCompanyIdAndBranchIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), users.getBranch().getId(), true);
                    } else {
                        tranxReceiptPerticularsDetails = tranxReceiptPerticularsDetailsRepository.findByIdAndCompanyIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), true);
                    }
                    if (tranxReceiptPerticularsDetails != null) {
                        inside.addProperty("particulars", tranxReceiptPerticularsDetails.getLedgerMaster().getLedgerName());
                        inside.addProperty("id", tranxReceiptPerticularsDetails.getId());
                    }
                } else if (tranx_type == 6) {
                    TranxPaymentPerticularsDetails tranxPaymentPerticulars;
                    if (users.getBranch() != null) {
                        tranxPaymentPerticulars = tranxPaymentPerticularsDetailsRepository.findByIdAndCompanyIdAndBranchIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), users.getBranch().getId(), true);
                    } else {
                        tranxPaymentPerticulars = tranxPaymentPerticularsDetailsRepository.findByIdAndCompanyIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), true);
                    }
                    if (tranxPaymentPerticulars != null) {
                        inside.addProperty("particulars", tranxPaymentPerticulars.getLedgerMaster().getLedgerName());
                        inside.addProperty("id", tranxPaymentPerticulars.getId());
                    }
                } else if (tranx_type == 9) {
                    TranxContraDetails tranxContraDetails;
                    if (users.getBranch() != null) {
                        tranxContraDetails = tranxContraDetailsRepository.findByIdAndCompanyIdAndBranchIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), users.getBranch().getId(), true);
                    } else {
                        tranxContraDetails = tranxContraDetailsRepository.findByIdAndCompanyIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), true);
                    }
                    if (tranxContraDetails != null) {
                        inside.addProperty("particulars", tranxContraDetails.getLedgerMaster().getLedgerName());
                        inside.addProperty("id", tranxContraDetails.getId());
                    }
                } else if (tranx_type == 10) {
                    TranxJournalDetails tranxJournalDetails;
                    if (users.getBranch() != null) {
                        tranxJournalDetails = tranxJournalDetailsRepository.findByIdAndCompanyIdAndBranchIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), users.getCompany().getId(), true);
                    } else {
                        tranxJournalDetails = tranxJournalDetailsRepository.findByIdAndCompanyIdAndStatus(ledgerTransactionDetails.getTransactionId(), users.getCompany().getId(), true);
                    }
                    if (tranxJournalDetails != null) {
                        inside.addProperty("particulars", tranxJournalDetails.getLedgerMaster().getLedgerName());
                        inside.addProperty("id", tranxJournalDetails.getId());
                    }
                }
                inside.addProperty("voucher_type", ledgerTransactionDetails.getTransactionType().getTransactionName());
                if (ledgerTransactionDetails.getLedgerType().equalsIgnoreCase("CR")) {
                    inside.addProperty("credit", ledgerTransactionDetails.getAmount());
                    inside.addProperty("debit", 0);
                    amt = ledgerTransactionDetails.getAmount();

                } else {
                    inside.addProperty("credit", 0);
                    inside.addProperty("debit", ledgerTransactionDetails.getAmount());
                    amt = ledgerTransactionDetails.getAmount();
                }
                if (amt != 0.0)
                    innerArr.add(inside);
            }
        }
        return innerArr;
    }

//    public JsonArray getMobileCommonDetails(List<LedgerTransactionPostings> mlist) {
//        JsonArray innerArr = new JsonArray();
//        for (LedgerTransactionPostings ledgerTransactionDetails : mlist) {
//            if (!ledgerTransactionDetails.getOperations().equalsIgnoreCase("Delete")) {
//                JsonObject inside = new JsonObject();
//                inside.addProperty("transaction_date", ledgerTransactionDetails.getTransactionDate().toString());
//                inside.addProperty("invoice_no", ledgerTransactionDetails.getInvoiceNo());
//                inside.addProperty("invoice_id", ledgerTransactionDetails.getTransactionId());// Invoice Id : 1 or 2
//                Long tranx_type = ledgerTransactionDetails.getTransactionType().getId(); // Transactions Id : 1:Pur 3: Sales
//                inside.addProperty("transaction_type", tranx_type);
//                if (tranx_type == 1) {
//                    TranxPurInvoice tranxPurInvoice;
//                    tranxPurInvoice = tranxPurInvoiceRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxPurInvoice != null) {
//                        inside.addProperty("particulars", tranxPurInvoice.getSundryCreditors().getLedgerName());
//                        inside.addProperty("id", tranxPurInvoice.getId());
//                    }
//                } else if (tranx_type == 2) {
//                    TranxPurReturnInvoice tranxPurReturnInvoice;
//
//                    tranxPurReturnInvoice = tranxPurReturnsRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxPurReturnInvoice != null) {
//                        inside.addProperty("particulars", tranxPurReturnInvoice.getSundryCreditors().getLedgerName());
//                        inside.addProperty("id", tranxPurReturnInvoice.getId());
//                    }
//                } else if (tranx_type == 3) {
//                    TranxSalesInvoice tranxSalesInvoice;
//
//                    tranxSalesInvoice = tranxSalesInvoiceRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxSalesInvoice != null) {
//                        inside.addProperty("particulars", tranxSalesInvoice.getSundryDebtors().getLedgerName());
//                        inside.addProperty("id", tranxSalesInvoice.getId());
//                    }
//                } else if (tranx_type == 4) {
//                    TranxSalesReturnInvoice tranxSalesReturnInvoice;
//
//                    tranxSalesReturnInvoice = tranxSalesReturnRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxSalesReturnInvoice != null) {
//                        inside.addProperty("particulars", tranxSalesReturnInvoice.getSundryDebtors().getLedgerName());
//                        inside.addProperty("id", tranxSalesReturnInvoice.getId());
//                    }
//                } else if (tranx_type == 5) {
//                    TranxReceiptPerticularsDetails tranxReceiptPerticularsDetails;
//
//                    tranxReceiptPerticularsDetails = tranxReceiptPerticularsDetailsRepository.findBylistStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxReceiptPerticularsDetails != null) {
//                        inside.addProperty("particulars", tranxReceiptPerticularsDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxReceiptPerticularsDetails.getId());
//                    }
//                } else if (tranx_type == 6) {
//                    TranxPaymentPerticularsDetails tranxPaymentPerticulars;
//
//                    tranxPaymentPerticulars = tranxPaymentPerticularsDetailsRepository.findListStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxPaymentPerticulars != null) {
//                        inside.addProperty("particulars", tranxPaymentPerticulars.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxPaymentPerticulars.getId());
//                    }
//                } else if (tranx_type == 7) {
//                    TranxDebitNoteDetails tranxDebitNoteDetails;
//
//                    tranxDebitNoteDetails = tranxDebitNoteDetailsRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxDebitNoteDetails != null) {
//                        inside.addProperty("particulars", tranxDebitNoteDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxDebitNoteDetails.getId());
//                    }
//                } else if (tranx_type == 8) {
//                    TranxCreditNoteDetails tranxCreditNoteDetails;
//
//                    tranxCreditNoteDetails = tranxCreditNoteDetailsRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxCreditNoteDetails != null) {
//                        inside.addProperty("particulars", tranxCreditNoteDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxCreditNoteDetails.getId());
//                    }
//                } else if (tranx_type == 9) {
//                    TranxContraDetails tranxContraDetails;
//
//                    tranxContraDetails = tranxContraDetailsRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxContraDetails != null) {
//                        inside.addProperty("particulars", tranxContraDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxContraDetails.getId());
//                    }
//                } else if (tranx_type == 10) {
//                    TranxJournalDetails tranxJournalDetails;
//
//                    tranxJournalDetails = tranxJournalDetailsRepository.findByIdAndStatus(ledgerTransactionDetails.getTransactionId(), true);
//
//                    if (tranxJournalDetails != null) {
//                        inside.addProperty("particulars", tranxJournalDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxJournalDetails.getId());
//                    }
//                }
//                inside.addProperty("voucher_type", ledgerTransactionDetails.getTransactionType().getTransactionName());
//                if (ledgerTransactionDetails.getLedgerType().equalsIgnoreCase("CR")) {
//                    inside.addProperty("credit", ledgerTransactionDetails.getAmount());
//                    inside.addProperty("debit", 0);
//                    inside.addProperty("TransactionType", "CR");
//
//                } else {
//                    inside.addProperty("credit", 0);
//                    inside.addProperty("debit", ledgerTransactionDetails.getAmount());
//                    inside.addProperty("TransactionType", "DR");
//
//                }
//                innerArr.add(inside);
//            }
//        }
//        return innerArr;
//    }

//    public Object getTransactionsDetailsReports(HttpServletRequest request) {
//        JsonObject res = new JsonObject();
//        List<LedgerTransactionPostings> mlist = new ArrayList<>();
//        Map<String, String[]> paramMap = request.getParameterMap();
//        Long tranx_type = Long.parseLong(request.getParameter("transaction_type"));
//        Long invoice_id = Long.parseLong(request.getParameter("id"));
//        return res;
//    }
//
//    public Object getMonthwiseTranscationDetails(HttpServletRequest request) {
//        JsonObject res = new JsonObject();
//        Long id = 0L;
//        Double total_month_sum = 0.0;
//        Double credit_total = 0.0;
//
//        List<Object[]> list = new ArrayList<>();
//        try {
//            Map<String, String[]> paramMap = request.getParameterMap();
//            String endDate = null;
//            LocalDate endDatep = null;
//            String startDate = null;
//            LocalDate startDatep = null;
//            Double opening_bal = 0.0;
//            Long ledger_master_id = Long.valueOf(request.getParameter("ledger_master_id"));
//            LedgerMaster ledgerMaster = ledgerMasterRepository.findByIdAndStatus(ledger_master_id, true);
//            LocalDate currentStartDate = null;
//            LocalDate currentEndDate = null;
//            Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//            //****This Code For Users Dates Selection Between Start And End Date Manually****//
//            if (paramMap.containsKey("end_date") && paramMap.containsKey("start_date")) {
//                endDate = request.getParameter("end_date");
//                endDatep = LocalDate.parse(endDate);
//                startDate = request.getParameter("start_date");
//                startDatep = LocalDate.parse(startDate);
//
//            } else {
//                //****This Code For Load Data Default Current Year From Automatically load And Select Fiscal Year From Fiscal Year Table****//
//                List<Object[]> nlist = new ArrayList<>();
//                nlist = fiscalYearRepository.findByStartDateAndEndDateOutletIdAndBranchIdAndStatusLimit();
//                for (int i = 0; i < nlist.size(); i++) {
//                    Object obj[] = nlist.get(i);
//                    System.out.println("start Date:" + obj[0].toString());
//                    System.out.println("end Date:" + obj[1].toString());
//                    startDatep = LocalDate.parse(obj[0].toString());
//                    endDatep = LocalDate.parse(obj[1].toString());
//                }
//
//                //**Openig Balance for Fiscal Year**//
//                if (users.getBranch() != null) {
//                    opening_bal = ledgerMasterRepository.findByIdAndOutletIdAndBranchIdAndStatuslm(users.getOutlet().getId(), users.getBranch().getId(), true, ledger_master_id);
//                } else {
//                    opening_bal = ledgerMasterRepository.findByIdAndOutletIdAndStatuslm(users.getOutlet().getId(), true, ledger_master_id);
//                }
//            }
//            currentStartDate = startDatep;
//            currentEndDate = endDatep;
//            if (startDatep.isAfter(endDatep)) {
//                System.out.println("Start Date Should not be After");
//                return 0;
//            }
//            JsonArray innerArr = new JsonArray();
//            while (startDatep.isBefore(endDatep)) {
//                Double closing_bal = 0.0;
//                String month = startDatep.getMonth().name();
//                System.out.println();
//                LocalDate startMonthDate = startDatep;
//                LocalDate endMonthDate = startDatep.withDayOfMonth(startDatep.lengthOfMonth());
//                System.out.println("Start Date:" + startMonthDate + "End Date " + endMonthDate); //**  If You Want To Print  All Start And End Date of each month  between Fiscal Year **//
//                startDatep = endMonthDate.plusDays(1);
//                System.out.println();
//                if (endDate != null) {
//                    //****This Code For Users Dates Selection Between Start And End Date Manually****//
//                    if (users.getBranch() != null) {
//                        list = postingsRepository.findByTotalAmountByMonthStartDateAndEndDateAndBranchAndOutletAndStatus3(users.getOutlet().getId(), users.getBranch().getId(), true, ledger_master_id, startMonthDate, endMonthDate);
//                    } else {
//                        list = postingsRepository.findByTotalAmountByMonthStartDateAndEndDateAndOutletAndStatus3(users.getOutlet().getId(), true, ledger_master_id, startMonthDate, endMonthDate);
//                    }
//                } else {
//                    //****This Code For Load Data Default Current Year From Automatically load And Select Fiscal Year From Fiscal Year Table****//
//                    try {
//                        if (users.getBranch() != null) {
//                            list = postingsRepository.findByTotalAmountByMonthStartDateAndEndDateAndBranchAndOutletAndStatus3(users.getOutlet().getId(), users.getBranch().getId(), true, ledger_master_id, startMonthDate, endMonthDate);
//                        } else {
//                            list = postingsRepository.findByTotalAmountByMonthStartDateAndEndDateAndOutletAndStatus3(users.getOutlet().getId(), true, ledger_master_id, startMonthDate, endMonthDate);
//                        }
//                    } catch (Exception e) {
//                        e.printStackTrace();
//                        System.out.println("Exception:" + e.getMessage());
//                    }
//                }
//                JsonObject inside = new JsonObject();
//                for (int i = 0; i < list.size(); i++) {
//                    Object[] objp = list.get(i);
//                    credit_total = Double.parseDouble(objp[0].toString());
//                    if (objp[1] != null)
//                        ledger_master_id = Long.parseLong(objp[1].toString());
//                    LedgerMaster mLedger = ledgerMasterRepository.findByIdAndStatus(ledger_master_id, true);
//                    inside.addProperty("total_balance", credit_total);
//                    if (ledgerMaster.getFoundations().getId() == 1 || ledgerMaster.getFoundations().getId() == 4) {
//                        if (credit_total > 0) {
//                            inside.addProperty("type", "DR");
//                        } else {
////                            inside.addProperty("type","CR");
//                        }
//                    } else {
//                        if (credit_total > 0) {
//                            inside.addProperty("type", "CR");
//                        } else {
//                            //                            inside.addProperty("type","DR");
//                        }
//
//                    }
//                    if (objp[2] != null) {
//                        if (objp[2].toString().equalsIgnoreCase("DR")) {
//                            inside.addProperty("debit", credit_total);
//                            inside.addProperty("credit", 0.0);
//
//                        } else {
//                            inside.addProperty("credit", credit_total);
//                            inside.addProperty("debit", 0.0);
//                        }
//                    } else {
//                        inside.addProperty("debit", 0.0);
//                        inside.addProperty("credit", 0.0);
//                    }
//
//                    inside.addProperty("month_name", month);
//                    inside.addProperty("start_date", startMonthDate.toString());
//                    inside.addProperty("end_date", endMonthDate.toString());
//                    innerArr.add(inside);
//                }
//            }
//            res.addProperty("company_name", ledgerMaster.getOutlet().getCompanyName());
//            res.addProperty("d_start_date", currentStartDate.toString());
//            res.addProperty("d_end_date", currentEndDate.toString());
//            res.add("response", innerArr);
//            res.addProperty("opening_bal", opening_bal);
//            res.addProperty("responseStatus", HttpStatus.OK.value());
//        } catch (Exception e) {
//            e.printStackTrace();
//            res.addProperty("message", "Failed To Load Data");
//            res.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return res;
//
//    }
//
//    public Object getTranxDetailofMonth(HttpServletRequest request) {
//        JsonArray result = new JsonArray();
//        JsonObject res = new JsonObject();
//        List<LedgerTransactionPostings> mlist = new ArrayList<>();
//        try {
//            Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//            Long ledger_master_id = Long.valueOf(request.getParameter("ledger_master_id"));
//            LocalDate startDate = LocalDate.parse(request.getParameter("start_date"));
//            LocalDate endDate = LocalDate.parse(request.getParameter("end_date"));
//            Long branchId = null;
//            if (users.getBranch() != null) {
//                branchId = users.getBranch().getId();
//            }
//            mlist = postingsRepository.findByIdAndOutletIdAndBranchAndStatusBalanceStep4(users.getOutlet().getId(), branchId, true, ledger_master_id, startDate, endDate);
//            System.out.println("mlist" + mlist.size());
//            JsonArray innerArr = new JsonArray();
//            for (LedgerTransactionPostings ledgerTransactionPostings : mlist) {
//                JsonObject inside = new JsonObject();
//                inside.addProperty("transaction_date", ledgerTransactionPostings.getTransactionDate().toString());
//                inside.addProperty("invoice_no", ledgerTransactionPostings.getInvoiceNo());
//                inside.addProperty("invoice_id", ledgerTransactionPostings.getTransactionId());
//                Long tranx_type = ledgerTransactionPostings.getTransactionType().getId();
//                if (tranx_type == 1) {
//                    TranxPurInvoice tranxPurInvoice;
//                    if (users.getBranch() != null) {
//                        tranxPurInvoice = tranxPurInvoiceRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxPurInvoice.getSundryCreditors().getLedgerName());
//                        inside.addProperty("id", tranxPurInvoice.getId());
//                    } else {
//                        tranxPurInvoice = tranxPurInvoiceRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), branchId, true);
//                        inside.addProperty("particular", tranxPurInvoice.getSundryCreditors().getLedgerName());
//                        inside.addProperty("id", tranxPurInvoice.getId());
//                    }
//                } else if (tranx_type == 2) {
//                    TranxPurReturnInvoice tranxPurReturnInvoice;
//                    if (users.getBranch() != null) {
//                        tranxPurReturnInvoice = tranxPurReturnsRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxPurReturnInvoice.getSundryCreditors().getLedgerName());
//                        inside.addProperty("id", tranxPurReturnInvoice.getId());
//                    } else {
//                        tranxPurReturnInvoice = tranxPurReturnsRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxPurReturnInvoice.getSundryCreditors().getLedgerName());
//                        inside.addProperty("id", tranxPurReturnInvoice.getId());
//                    }
//                } else if (tranx_type == 3) {
//                    TranxSalesInvoice tranxSalesInvoice;
//                    if (users.getBranch() != null) {
//                        tranxSalesInvoice = tranxSalesInvoiceRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxSalesInvoice.getSundryDebtors().getLedgerName());
//                        inside.addProperty("id", tranxSalesInvoice.getId());
//                    } else {
//                        tranxSalesInvoice = tranxSalesInvoiceRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxSalesInvoice.getSundryDebtors().getLedgerName());
//                        inside.addProperty("id", tranxSalesInvoice.getId());
//                    }
//                } else if (tranx_type == 4) {
//                    TranxSalesReturnInvoice tranxSalesReturnInvoice;
//                    if (users.getBranch() != null) {
//                        tranxSalesReturnInvoice = tranxSalesReturnRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxSalesReturnInvoice.getSundryDebtors().getLedgerName());
//                        inside.addProperty("id", tranxSalesReturnInvoice.getId());
//                    } else {
//                        tranxSalesReturnInvoice = tranxSalesReturnRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxSalesReturnInvoice.getSundryDebtors().getLedgerName());
//                        inside.addProperty("id", tranxSalesReturnInvoice.getId());
//                    }
//                } else if (tranx_type == 5) {
//                    TranxReceiptPerticularsDetails tranxReceiptPerticularsDetails;
//                    if (users.getBranch() != null) {
//                        tranxReceiptPerticularsDetails = tranxReceiptPerticularsDetailsRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxReceiptPerticularsDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxReceiptPerticularsDetails.getId());
//                    } else {
//                        tranxReceiptPerticularsDetails = tranxReceiptPerticularsDetailsRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxReceiptPerticularsDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxReceiptPerticularsDetails.getId());
//                    }
//                } else if (tranx_type == 6) {
//                    TranxPaymentPerticularsDetails tranxPaymentPerticulars;
//                    if (users.getBranch() != null) {
//                        tranxPaymentPerticulars = tranxPaymentPerticularsDetailsRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxPaymentPerticulars.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxPaymentPerticulars.getId());
//                    } else {
//                        tranxPaymentPerticulars = tranxPaymentPerticularsDetailsRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxPaymentPerticulars.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxPaymentPerticulars.getId());
//                    }
//                } else if (tranx_type == 7) {
//                    TranxDebitNoteDetails tranxDebitNoteDetails;
//                    if (users.getBranch() != null) {
//                        tranxDebitNoteDetails = tranxDebitNoteDetailsRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxDebitNoteDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxDebitNoteDetails.getId());
//                    } else {
//                        tranxDebitNoteDetails = tranxDebitNoteDetailsRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxDebitNoteDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxDebitNoteDetails.getId());
//                    }
//                } else if (tranx_type == 8) {
//                    TranxCreditNoteDetails tranxCreditNoteDetails;
//                    if (users.getBranch() != null) {
//                        tranxCreditNoteDetails = tranxCreditNoteDetailsRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxCreditNoteDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxCreditNoteDetails.getId());
//                    } else {
//                        tranxCreditNoteDetails = tranxCreditNoteDetailsRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxCreditNoteDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxCreditNoteDetails.getId());
//                    }
//                } else if (tranx_type == 9) {
//                    TranxContraDetails tranxContraDetails;
//                    if (users.getBranch() != null) {
//                        tranxContraDetails = tranxContraDetailsRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxContraDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxContraDetails.getId());
//                    } else {
//                        tranxContraDetails = tranxContraDetailsRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxContraDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxContraDetails.getId());
//                    }
//                } else if (tranx_type == 10) {
//                    TranxJournalDetails tranxJournalDetails;
//                    if (users.getBranch() != null) {
//                        tranxJournalDetails = tranxJournalDetailsRepository.findByIdAndOutletIdAndBranchIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), users.getBranch().getId(), true);
//                        inside.addProperty("particulars", tranxJournalDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxJournalDetails.getId());
//                    } else {
//                        tranxJournalDetails = tranxJournalDetailsRepository.findByIdAndOutletIdAndStatus(ledgerTransactionPostings.getTransactionId(), users.getOutlet().getId(), true);
//                        inside.addProperty("particulars", tranxJournalDetails.getLedgerMaster().getLedgerName());
//                        inside.addProperty("id", tranxJournalDetails.getId());
//                    }
//                }
//                inside.addProperty("voucher_type", ledgerTransactionPostings.getTransactionType().getTransactionName());
//                LedgerMaster ledgerMaster = ledgerMasterRepository.findByIdAndStatus(ledger_master_id, true);
//                inside.addProperty("ledgerName", ledgerMaster.getLedgerName());
//                res.addProperty("companyName", ledgerMaster.getOutlet().getCompanyName());
//                if (ledgerTransactionPostings.getLedgerType().equalsIgnoreCase("CR")) {
//                    inside.addProperty("credit", ledgerTransactionPostings.getAmount());
//                    inside.addProperty("debit", 0.00);
//                } else {
//                    inside.addProperty("debit", ledgerTransactionPostings.getAmount());
//                    inside.addProperty("credit", 0.00);
//                }
////                inside.addProperty("debit", ledgerTransactionPostings.getLedgerMaster().getDebit());
////                inside.addProperty("credit", ledgerTransactionPostings.getCredit());
//
//                innerArr.add(inside);
//            }
//            res.addProperty("d_start_date", startDate.toString());
//            res.addProperty("d_end_date", endDate.toString());
//            res.add("response", innerArr);
//            res.addProperty("responseStatus", HttpStatus.OK.value());
//        } catch (Exception e) {
//            e.printStackTrace();
//            res.addProperty("message", "Failed To Load Data");
//            res.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return res;
//    }
//
//    public Object getMobileLedgerTransactionsDetails(Map<String, String> request) {
//        JsonArray result = new JsonArray();
//        JsonObject finalResponse = new JsonObject();
//
//        JsonArray response = new JsonArray();
//        List<LedgerTransactionPostings> mlist = new ArrayList<>();
////        Map<String, String[]> paramMap = request.get();
//        try {
////            Users users = jwtRequestFilter.getUserDataFromToken(request.get("Authorization").substring(7));
//            Long ledger_master_id = Long.valueOf(request.get("ledgerId"));
//            String startDate = "";
//            String endDate = "";
//            LocalDate endDatep = null;
//            LocalDate startDatep = null;
//            Long branchId = null;
//            FiscalYear fiscalYear = null;
//            Boolean flag = false;
//            LedgerMaster ledgerMaster = ledgerMasterRepository.findByIdAndStatus(ledger_master_id, true);
//
//            if (!request.get("end_date").equalsIgnoreCase("") && !request.get("start_date").equalsIgnoreCase("")) {
//                endDatep = LocalDate.parse(request.get("end_date").toString());
//
//                startDatep = LocalDate.parse(request.get("start_date"));
//                flag = true;
//            } else {
//                List<Object[]> list = new ArrayList<>();
//                fiscalYear = generateFiscalYear.getFiscalYear(LocalDate.now());
//                flag = false;
//            }
//            mlist = transactionDetailsRepository.findByMobileDetailsFisc(true, ledger_master_id);
//
//            JsonArray innerArr = new JsonArray();
//            innerArr = getMobileCommonDetails(mlist);
//
//            Double openingStock = 0.0;
//            openingStock = ledgerCommonPostings.getmobileOpeningStock(ledger_master_id,
//                    startDatep, endDatep, flag, fiscalYear);
//
//            finalResponse.addProperty("crdrType", ledgerMaster.getOpeningBalType().toLowerCase());
//            finalResponse.add("response", innerArr);
//            finalResponse.addProperty("opening_stock", Math.abs(openingStock));
//            finalResponse.addProperty("responseStatus", HttpStatus.OK.value());
//        } catch (Exception e) {
//            e.printStackTrace();
//            finalResponse.addProperty("message", "Failed To Load Data");
//            finalResponse.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return finalResponse;
//    }

}
