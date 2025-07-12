package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.BreakMaster;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BreakMasterRepository extends JpaRepository<BreakMaster, Long> {
    BreakMaster findByIdAndStatus(Long id, boolean b);

    List<BreakMaster> findAllByCompanyIdAndStatus(Long companyId, boolean b);

    List<BreakMaster> findAllByStatus( boolean b);

    List<BreakMaster> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);

    List<BreakMaster> findAllByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);
}
