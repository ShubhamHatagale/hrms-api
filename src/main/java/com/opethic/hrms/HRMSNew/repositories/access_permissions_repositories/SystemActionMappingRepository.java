package com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories;

import com.opethic.hrms.HRMSNew.models.access_permissions.SystemActionMapping;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SystemActionMappingRepository extends JpaRepository<SystemActionMapping, Long> {

    List<SystemActionMapping> findByStatus(boolean b);

    SystemActionMapping findByIdAndStatus(long mapping_id, boolean b);

    SystemActionMapping findBySystemMasterModulesIdAndStatus(Long mapElement, boolean b);
}
