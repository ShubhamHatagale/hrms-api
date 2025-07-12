package com.opethic.hrms.HRMSNew.repositories.tranx_repository.contra_repository;

import com.opethic.hrms.HRMSNew.models.tranx.contra.TranxContraDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface TranxContraDetailsRepository extends JpaRepository<TranxContraDetails,Long> {
    /*@Query(
            value = "SELECT * FROM tranx_contra_details_tbl WHERE" +
                    " tranx_contra_master_id=?1 AND (ledger_type='others' OR ledger_type='bank_account') And company_id=?2 AND status =?3 ",
            nativeQuery = true

    )
    TranxContraDetails findLedgerName(Long id, Long outlteId, boolean status);
*/
    @Query(
            value = "SELECT * FROM tranx_contra_details_tbl WHERE" +
                    " tranx_contra_master_id=?1 And company_id=?2 AND status =?3 ",
            nativeQuery = true

    )
    List<TranxContraDetails> findLedgerName(Long id, Long outlteId, boolean status);
    TranxContraDetails findByIdAndStatus(Long detailsId, boolean b);

    List<TranxContraDetails> findByTranxContraMasterIdAndStatus(Long id, boolean b);

    TranxContraDetails findByIdAndCompanyIdAndBranchIdAndStatus(Long tranx_type, Long id, Long id1, boolean b);

    TranxContraDetails findByIdAndCompanyIdAndStatus(Long tranx_type, Long id, boolean b);

    TranxContraDetails findByTranxContraMasterIdAndCompanyIdAndBranchIdAndStatusAndType(Long transactionId, Long id, Long id1, boolean b, String dr);

    TranxContraDetails findByTranxContraMasterIdAndCompanyIdAndStatusAndType(Long transactionId, Long id, boolean b, String dr);


}
