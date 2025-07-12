package com.opethic.hrms.HRMSNew.repositories.tranx_repository.journal_repository;

import com.opethic.hrms.HRMSNew.models.tranx.journal.TranxJournalMaster;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;


public interface TranxJournalMasterRepository extends JpaRepository<TranxJournalMaster,Long> {
    @Query(
            value = "select COUNT(*) from tranx_journal_master_tbl WHERE company_id=?1 AND branch_id IS NULL", nativeQuery = true
    )
    Long findLastRecord(Long id);

    List<TranxJournalMaster> findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(Long id, Long id1, boolean b);

    TranxJournalMaster findByIdAndStatus(long journal_id, boolean b);

    TranxJournalMaster findByIdAndCompanyIdAndStatus(Long journalId, Long id, boolean b);

    List<TranxJournalMaster> findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(Long id, boolean b);

    @Query(
            value = " SELECT COUNT(*) FROM tranx_journal_master_tbl WHERE company_id=?1 AND branch_id=?2", nativeQuery = true
    )
    Long findBranchLastRecord(Long id, Long id1);
}
