package com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories;

import com.opethic.hrms.HRMSNew.models.access_permissions.SystemMasterActions;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SystemMasterActionsRepository extends JpaRepository<SystemMasterActions,Long> {
    List<SystemMasterActions> findByStatus(boolean b);

    SystemMasterActions findByIdAndStatus(long parseLong, boolean b);
}
