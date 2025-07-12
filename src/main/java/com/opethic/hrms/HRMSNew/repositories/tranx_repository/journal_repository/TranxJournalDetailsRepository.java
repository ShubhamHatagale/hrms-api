package com.opethic.hrms.HRMSNew.repositories.tranx_repository.journal_repository;

import com.opethic.hrms.HRMSNew.models.tranx.journal.TranxJournalDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TranxJournalDetailsRepository extends JpaRepository<TranxJournalDetails,Long> {
    TranxJournalDetails findByIdAndStatus(Long detailsId, boolean b);

    List<TranxJournalDetails> findByTranxJournalMasterIdAndStatus(Long id, boolean b);

    TranxJournalDetails findByIdAndCompanyIdAndBranchIdAndStatus(Long tranx_type, Long id, Long id1, boolean b);

    TranxJournalDetails findByIdAndCompanyIdAndStatus(Long tranx_type, Long id, boolean b);

   List<TranxJournalDetails>  findByTranxJournalMasterIdAndTypeAndStatus(Long id, String dr, boolean b);

    TranxJournalDetails findByTranxJournalMasterIdAndCompanyIdAndBranchIdAndStatusAndType(Long transactionId, Long id, Long id1, boolean b, String dr);

    TranxJournalDetails findByTranxJournalMasterIdAndCompanyIdAndStatusAndType(Long transactionId, Long id, boolean b, String dr);
}
