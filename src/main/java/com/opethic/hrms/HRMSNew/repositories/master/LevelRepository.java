package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Level;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LevelRepository extends JpaRepository<Level, Long> {
    Level findByIdAndStatus(Long levelId, boolean b);

    List<Level> findAllByCompanyIdAndBranchIdAndStatus(Long companyId, Long branchId, boolean b);

    List<Level> findAllByAndStatus(boolean b);
}
