package com.opethic.hrms.HRMSNew.common;

import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionPostingsRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDate;

@Component
public class LedgerCommonPostings {
    @Autowired
    private LedgerTransactionPostingsRepository ledgerTransactionPostingsRepository;
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    private static final Logger postingLogger = LogManager.getLogger(LedgerCommonPostings.class);

    public void callToPostings(Double totalAmount, LedgerMaster ledgerMaster, TransactionTypeMaster tranxTypeMaster,
                               AssociateGroups associateGroups, FiscalYear fiscalYear, Branch branch, Company company,
                               LocalDate invoiceDate, Long invoiceId, String vendorInvoiceNo, String crdrType,
                               boolean status, String tranxType, String operations) {
        try {
            LedgerTransactionPostings ledgerTransactionPostings = new LedgerTransactionPostings();
            ledgerTransactionPostings.setAmount(totalAmount);
            ledgerTransactionPostings.setLedgerMaster(ledgerMaster);
            ledgerTransactionPostings.setTransactionType(tranxTypeMaster);
            ledgerTransactionPostings.setAssociateGroups(associateGroups);
            ledgerTransactionPostings.setFiscalYear(fiscalYear);
            ledgerTransactionPostings.setBranch(branch);
            ledgerTransactionPostings.setCompany(company);
            ledgerTransactionPostings.setTransactionDate(invoiceDate);
            ledgerTransactionPostings.setTransactionId(invoiceId);
            ledgerTransactionPostings.setInvoiceNo(vendorInvoiceNo);
            ledgerTransactionPostings.setLedgerType(crdrType);
            ledgerTransactionPostings.setTranxType(tranxType);
            ledgerTransactionPostings.setOperations(operations);
            ledgerTransactionPostings.setStatus(status);
            ledgerTransactionPostingsRepository.save(ledgerTransactionPostings);
        } catch (Exception e) {
            postingLogger.error("Exception in Postings :" + e.getMessage());
        }
    }

    public Double getOpeningStock(Long ledgerId, Long outletId, Long branchId, LocalDate startDate, LocalDate endDate,
                                  Boolean flag, FiscalYear fiscalYear) {
        Double openingStocks = 0.0;
        Double closing = 0.0;
        Double crOpening = 0.0;
        Double drOpening = 0.0;
        Double opening = 0.0;
        Double drClosing = 0.0;
        Double crClosing = 0.0;

        try {
            if (flag == true) {
                if(branchId!=null) {
                    LocalDate previousDate = startDate.minusDays(1);
                    crOpening = ledgerTransactionPostingsRepository.findLedgerOpeningBranch(ledgerId, outletId, branchId,"CR", previousDate);
                    drOpening = ledgerTransactionPostingsRepository.findLedgerOpeningBranch(ledgerId, outletId, branchId,"DR", previousDate);
                    openingStocks= crOpening-drOpening;
                }
                else {
                    LocalDate previousDate = startDate.minusDays(1);
                    crOpening = ledgerTransactionPostingsRepository.findLedgerOpening(ledgerId, outletId,"CR", previousDate);
                    drOpening = ledgerTransactionPostingsRepository.findLedgerOpening(ledgerId, outletId,"DR", previousDate);
                    openingStocks= crOpening-drOpening;
                }
                if (openingStocks != null) {
                    opening = openingStocks;
                }

            } else {
//                openingStocks = inventoryDetailsPostingsRepository.findFiscalyearOpening(productId,outletId, branchId,fiscalYear.getId());
                if(branchId!=null) {
                    crOpening = ledgerMasterRepository.findLedgerOpeningStocksBranch(ledgerId, outletId, branchId,"CR");
                    drOpening = ledgerMasterRepository.findLedgerOpeningStocksBranch(ledgerId, outletId, branchId,"DR");
                    openingStocks= crOpening-drOpening;
                }
                else {
                    crOpening = ledgerMasterRepository.findLedgerOpeningStocks(ledgerId, outletId, branchId,"CR");
                    drOpening = ledgerMasterRepository.findLedgerOpeningStocks(ledgerId, outletId, branchId,"DR");
                    openingStocks= crOpening-drOpening;


                }
                if (openingStocks != null) {
                    opening = openingStocks;
                }
//                drClosing = inventoryDetailsPostingsRepository.findFiscalyearClosing(productId, outletId, branchId, "DR", fiscalYear.getId());
//                crClosing = inventoryDetailsPostingsRepository.findFiscalyearClosing(productId, outletId, branchId, "CR", fiscalYear.getId());
//                opening = drClosing + crClosing;
            }

            System.out.println("\nProduct Id:" + ledgerId + " opening Stocks:" + opening);
        } catch (Exception e) {
            System.out.println("Exception :" + e.getMessage());
        }
        return opening;
    }
}

