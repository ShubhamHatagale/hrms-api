package com.opethic.hrms.HRMSNew.common;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import com.opethic.hrms.HRMSNew.models.access_permissions.SystemMasterActions;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemMasterModules;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemActionMappingRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemMasterActionsRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemMasterModuleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CommonAccessPermissions {
    @Autowired
    private SystemMasterModuleRepository moduleRepository;
    @Autowired
    private SystemMasterActionsRepository actionsRepository;
    @Autowired
    private SystemActionMappingRepository systemActionMappingRepository;
    public List<SystemMasterModules> modulesParentIds = new ArrayList<>();

    public JsonArray getActions(String[] actions) {
        JsonArray mArray = new JsonArray();
        JsonArray mMasters = new JsonArray();
        //  JsonObject mObject = new JsonObject();
        for (String actionId : actions) {
            JsonObject mAction = new JsonObject();
            SystemMasterActions masterActions = actionsRepository.findByIdAndStatus(Long.parseLong(actionId), true);
            mAction.addProperty("id", masterActions.getId());
            mAction.addProperty("name", masterActions.getName());
            mAction.addProperty("slug", masterActions.getSlug());
            mArray.add(mAction);
        }
        return mArray;
    }

    public JsonArray getParentMasters(Long masterModuleId) {
        JsonArray mActions = new JsonArray();
        modulesParentIds.clear();
        if (masterModuleId != null) {
            getModules(masterModuleId);
        } else {

        }

        for (SystemMasterModules systemMasterModules : modulesParentIds) {
            JsonObject mObject = new JsonObject();
            mObject.addProperty("id", systemMasterModules.getId());
            mObject.addProperty("name", systemMasterModules.getName());
            mObject.addProperty("slug", systemMasterModules.getSlug());
            mActions.add(mObject);
        }
        return mActions;
    }

    public void getModules(Long mapElement) {
        modulesParentIds.add(recursiveCall(mapElement));
    }

    public SystemMasterModules recursiveCall(Long mapElement) {
        SystemMasterModules modules = moduleRepository.findByIdAndStatus(mapElement, true);
        if (modules.getParentModuleId() == null) {
            return modules;
        } else {
            modulesParentIds.add(modules);
            return recursiveCall(modules.getParentModuleId());
        }
    }


}

