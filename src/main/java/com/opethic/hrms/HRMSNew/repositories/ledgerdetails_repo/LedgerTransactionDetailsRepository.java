package com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo;

import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.query.Procedure;

import java.time.LocalDate;
import java.util.List;

public interface LedgerTransactionDetailsRepository extends JpaRepository<LedgerTransactionDetails, Long> {

    List<LedgerTransactionDetails> findByLedgerMasterIdAndCompanyIdAndTransactionTypeId(long id, Long id1, long l);
/*

    @Query(
            value = " SELECT * FROM ledger_transaction_details_tbl WHERE" +
                    " ledger_master_id=?1 ORDER BY ID DESC LIMIT 1 ", nativeQuery = true
    )
    LedgerTransactionDetails findLastRecord(Long id);
*/

    @Procedure("LEDGER_TRANSACTION_DETAILS_POSTINGS_INSERT")
    void insertIntoLegerTranxDetailsPosting(Long foundation_id, Long principle_id, Long principle_group_id, Long associates_group_id, Long tranx_type_master_id, Long balancing_method_id, Long branch_id, Long company_id, String payment_status, Double debit, Double credit, LocalDate transactionDate, LocalDate payment_date, Long tranx_id, String transaction_name, String under_prefix, String financial_year, Long created_by, Long ledger_master_id, String voucher_no);

    @Query(
            value = " SELECT ledger_master_id FROM ledger_transaction_details_tbl WHERE" +
                    " transaction_id=?1 AND transaction_type_id =?2 ", nativeQuery = true
    )
    List<Long> findByTransactionId(Long id, Long tranxTypeId);


    @Procedure("LEDGER_POSTING_EDIT_TRANX")
    void ledgerPostingEdit(Long ledgerMasterId, Long transactionId,
                           Long transactionTypeId, String tranxType, Double totalamt);

    @Procedure("LEDGER_POSTING_TRANX_REMOVE")
    void ledgerPostingRemove(Long ledgerMasterId, Long transactionId,
                             Long transactionTypeId);

    @Query(
            value = "SELECT * FROM `ledger_transaction_details_tbl` where principle_groups_id IN (1,4,5) Or (principle_id IN(9,12) " +
                    "AND (transaction_type_id!=1 AND transaction_type_id!=3 AND transaction_type_id!=2 " +
                    "AND transaction_type_id!=4 AND transaction_type_id!=6)) OR (principle_groups_id=6 AND principle_id=6 AND transaction_type_id=10)" + " AND company_id=?1", nativeQuery = true
    )
    List<LedgerTransactionDetails> findbygroupId(Long id);

    @Query(
            value = "SELECT * FROM `ledger_transaction_details_tbl` where principle_groups_id IN (1,2,4,5) Or (principle_id IN(9,12) " +
                    "AND (transaction_type_id!=1 AND transaction_type_id!=3 AND transaction_type_id!=2 " +
                    "AND transaction_type_id!=4)) OR (principle_groups_id=6 AND principle_id=6 AND transaction_type_id=10)" + " AND company_id=?1 AND branch_id=?2",
            nativeQuery = true
    )
    List<LedgerTransactionDetails> findbygroupIdAndBranch(Long id, Long id1);

    List<LedgerTransactionDetails> findByLedgerMasterIdAndCompanyIdAndBranchIdAndTransactionTypeId(long id, Long id1, Long id2, long l);

    @Query(
            value = "SELECT IFNULL(SUM(closing_bal),0.0),IFNULL(ledger_transaction_details_tbl.principle_id,0) FROM `ledger_transaction_details_tbl` LEFT JOIN ledger_master_tbl ON " +
                    "ledger_transaction_details_tbl.ledger_master_id=ledger_master_tbl.id WHERE ledger_transaction_details_tbl.company_id=?1 " +
                    "AND ledger_transaction_details_tbl.branch_id=?2 AND ledger_transaction_details_tbl.status=?3 AND " +
                    "unique_code=?4 AND ledger_transaction_details_tbl.transaction_date BETWEEN  ?5 AND ?6 " +
                    "ORDER BY ledger_transaction_details_tbl.transaction_date ASC",
            nativeQuery = true
    )
    List<Object[]> findByDateWiseTotalAmountOuletAndBranchStatus(Long id, Long id1, boolean b, String diex, LocalDate startDate, LocalDate endDate);

    @Query(
            value = "SELECT IFNULL(SUM(closing_bal),0.0),IFNULL(ledger_transaction_details_tbl.principle_id,0) FROM `ledger_transaction_details_tbl` LEFT JOIN ledger_master_tbl ON " +
                    "ledger_transaction_details_tbl.ledger_master_id=ledger_master_tbl.id WHERE ledger_transaction_details_tbl.company_id=?1 AND" +
                    " ledger_transaction_details_tbl.status=?2 AND unique_code=?3 AND" +
                    " ledger_transaction_details_tbl.transaction_date BETWEEN  ?4 AND ?5 ORDER BY ledger_transaction_details_tbl.transaction_date ASC;",
            nativeQuery = true
    )
    List<Object[]> findByDateWiseTotalAmountOuletAndStatus(Long id, boolean b, String INEX, LocalDate startDate, LocalDate endDate);

    @Query(
            value = "SELECT SUM(closing_bal),principle_id  FROM `ledger_transaction_details_tbl` WHERE ledger_transaction_details_tbl.company_id=?1 AND ledger_transaction_details_tbl.branch_id=?2 " +
                    " AND ledger_transaction_details_tbl.status=?3 AND principle_id=?4 AND transaction_date BETWEEN ?5 AND ?6 GROUP BY ledger_master_id;", nativeQuery = true
    )
    List<Object[]> findByDateWiseTotalAmountOuletAndBranchStatusStep1(Long id, Long id1, boolean b, Long principle_id, LocalDate startDate, LocalDate endDate);

    @Query(
            value = "SELECT IFNULL(SUM(closing_bal),0),ledger_master_id FROM `ledger_transaction_details_tbl` WHERE ledger_transaction_details_tbl.company_id=?1 AND " +
                    "ledger_transaction_details_tbl.status=?2 AND principle_id=?3 AND" +
                    " transaction_date BETWEEN ?4 AND ?5 GROUP BY ledger_master_id;", nativeQuery = true
    )
    List<Object[]> findByDateWiseTotalAmountOuletAndStatusStep1(Long id, boolean b, Long principle_id, LocalDate startDate, LocalDate endDate);

    // For Get Sum of Closing Balance from Month start Date And End date
    @Query(
            value = "SELECT IFNULL(SUM(closing_bal),0),  IFNULL(opening_bal,0) FROM `ledger_transaction_details_tbl` WHERE company_id=?1 AND branch_id=?2 status=?3 AND" +
                    "ledger_master_id=?4 AND DATE(transaction_date) BETWEEN ?5 ANd ?6 ;", nativeQuery = true
    )
   Double findByTotalAmountByMonthStartDateAndEndDateAndBranchAndCompanyAndStatus(Long id, Long id1, boolean b, Long principle_id, LocalDate startDate, LocalDate endDate);

    @Query(
            value = "SELECT IFNULL(SUM(closing_bal),0) ,IFNULL(opening_bal,0) FROM `ledger_transaction_details_tbl` WHERE company_id=?1 AND status=?2 AND " +
                    "ledger_master_id=?3 AND DATE(transaction_date) BETWEEN ?4 ANd ?5 ;", nativeQuery = true
    )
   Double findByTotalAmountByMonthStartDateAndEndDateAndCompanyAndStatus(Long id, boolean b, Long principle_id, LocalDate startDate, LocalDate endDate);

    //For Profit And Loss Account Step 3
    @Query(
            value = "SELECT * FROM `ledger_transaction_details_tbl` WHERE company_id=?1 AND (branch_id=?2 OR branch_id IS NULL) AND  status=?3 AND " +
                    "ledger_master_id=?4 AND DATE(transaction_date) BETWEEN ?5 ANd ?6 ;", nativeQuery = true
    )
    List<LedgerTransactionDetails> findByIdAndCompanyIdAndBranchAndStatusStep3(Long id, Long id1, boolean b, Long ledger_master_id, LocalDate startDate, LocalDate endDate);

    @Query(
            value = "SELECT * FROM `ledger_transaction_details_tbl` WHERE  company_id=?1 AND " +
                    " status=?2  AND ledger_master_id=?3 AND transaction_date BETWEEN ?4 AND ?5", nativeQuery = true
    )
    List<LedgerTransactionDetails> findByIdAndCompanyIdAndStatusStep3(Long id, boolean b, Long ledger_master_id, LocalDate startDate, LocalDate endDate);
    @Query(
            value = "SELECT ledger_transaction_details_tbl.opening_bal FROM ledger_transaction_details_tbl WHERE company_id=?1 AND branch_id=?2 AND status=?3 AND" +
                    " id=?4 AND transaction_date=?5", nativeQuery = true
    )
    Double findByIdAndCompanyIdAndBranchIdAndStatuslt(Long id, Long id1, boolean b, Long principle_id, LocalDate startDatep);
    @Query(
            value = "SELECT ledger_transaction_details_tbl.opening_bal FROM ledger_transaction_details_tbl WHERE company_id=?1 AND status=?2 AND" +
                    " id=?3 AND transaction_date=?4", nativeQuery = true
    )
    Double findByIdAndCompanyIdAndStatusoplt(Long id, boolean b, Long principle_id, LocalDate startDatep);

}
