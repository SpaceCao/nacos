package com.alibaba.nacos.plugin.auth.impl.roles.abac;

import com.alibaba.nacos.auth.config.AuthConfigs;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.config.server.model.Page;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.api.Resource;
import com.alibaba.nacos.plugin.auth.constant.ActionTypes;
import com.alibaba.nacos.plugin.auth.constant.SignType;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.persistence.RoleInfo;
import com.alibaba.nacos.plugin.auth.impl.persistence.abac.AbacRomePermissionInfo;
import com.alibaba.nacos.plugin.auth.impl.persistence.abac.AbacRomePermissionPersistService;
import com.alibaba.nacos.plugin.auth.impl.roles.NacosRoleServiceImpl;
import io.jsonwebtoken.lang.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;


/**
 * @author caoxingming
 * @name AbacRomeNacosRoleServiceImpl
 * @data 2023-03-31-3:03 PM
 * @description: 基于Abac来伊份个性化权限service.
 */
@Service
public class AbacRomeNacosRoleServiceImpl {

    private static final int DEFAULT_PAGE_NO = 0;

    private static final int DEFAULT_PAGE_SIZE = 0;


    @Autowired
    private AuthConfigs authConfigs;

    @Autowired
    private NacosRoleServiceImpl nacosRoleService;

    @Autowired
    private AbacRomePermissionPersistService abacRomePermissionPersistService;

    private volatile Map<String, List<AbacRomePermissionInfo>> romePermissionInfoMap = new ConcurrentHashMap<>();


    @Scheduled(initialDelay = 5000, fixedDelay = 15000)
    private void reload() {
        try {
            Map<String, List<AbacRomePermissionInfo>> tmpRomePermissionInfoMap = new ConcurrentHashMap<>(16);

            while (true) {
                int pageNo = DEFAULT_PAGE_NO;
                Page<AbacRomePermissionInfo> romePermissionInfoPage = abacRomePermissionPersistService
                        .findRomePermissionByUsernameAndDataid(StringUtils.EMPTY, StringUtils.EMPTY, pageNo, DEFAULT_PAGE_SIZE);
                if (Objects.isNull(romePermissionInfoPage) || romePermissionInfoPage.getTotalCount() == 0)
                    break;
                for (AbacRomePermissionInfo abacRomePermissionInfo : romePermissionInfoPage.getPageItems()) {
                    if (!tmpRomePermissionInfoMap.containsKey(abacRomePermissionInfo.getUsername())) {
                        tmpRomePermissionInfoMap.put(abacRomePermissionInfo.getUsername(), new ArrayList<>());
                    }
                    tmpRomePermissionInfoMap.get(abacRomePermissionInfo.getUsername()).add(abacRomePermissionInfo);
                }
                pageNo++;
            }
            romePermissionInfoMap = tmpRomePermissionInfoMap;
        } catch (Exception e) {
            Loggers.AUTH.warn("[LOAD-ROME-PERMISSION] load failed", e);
        }
    }

    /*
     * 判断用户是否具有响应的访问/操作权限
     * @param username
     * @param permission
     * @return
     */
    @SuppressWarnings("checkstyle:MissingJavadocMethod")
    public boolean hasPermission(String username, Permission permission) {
        //兼容 nacos 自带的权限验证体系
        if (!nacosRoleService.hasPermission(username, permission)) return false;

        //来伊份个性化的权限管理验证
        if (!this.romeUserHasPermission(username, permission)) return false;

        return true;
    }

    /*
     * 来伊份个性化权限验证
     * @param username
     * @param permission
     * @return
     */
    @SuppressWarnings("checkstyle:MissingJavadocMethod")
    public boolean romeUserHasPermission(String username, Permission permission) {
        if (AuthConstants.UPDATE_PASSWORD_ENTRY_POINT.equals(permission.getResource().getName())) {
            return true;
        }

        List<RoleInfo> roleInfoList = nacosRoleService.getRoles(username);

        if (Collections.isEmpty(roleInfoList)) {
            return false;
        }

        for (RoleInfo roleInfo : roleInfoList) {
            if (AuthConstants.GLOBAL_ADMIN_ROLE.equals(roleInfo.getRole())) {
                return true;
            }
            if (AuthConstants.REMOTE_READONLY_ROLE.equals(roleInfo.getRole()) && ActionTypes.READ.toString().equals(permission.getAction())) {
                return true;
            }
            if (AuthConstants.GLOBAL_READONLY_ROLE.equals(roleInfo.getRole()) && ActionTypes.READ.toString().equals(permission.getAction())) {
                return true;
            }
        }

        Resource resource = permission.getResource();
        if (!SignType.CONFIG.equals(resource.getType()))
            return true;
        if (StringUtils.isEmpty(resource.getName()))
            return true;

        //校验用户权限
        List<AbacRomePermissionInfo> abacRomePermissionInfoList = getRomePermissions(permission, username);
        if (!Collections.isEmpty(abacRomePermissionInfoList)) {
            for (AbacRomePermissionInfo abacRomePermissionInfo : abacRomePermissionInfoList) {
                if (this.checkRomePermission(permission, abacRomePermissionInfo))
                    return true;
            }
        }

        return false;
    }

    /*
     * 来伊份个性化权限验证(验证一批应用权限),如果存在无权限的应用则返回false, 如果全部应用都有权限则返回 true
     * @param username
     * @param permission
     * @return
     */
    @SuppressWarnings("checkstyle:MissingJavadocMethod")
    public boolean romeUserHasAllPermission(String username, List<Permission> permissions) {
        List<RoleInfo> roleInfoList = nacosRoleService.getRoles(username);

        if (Collections.isEmpty(roleInfoList)) {
            return false;
        }

        // Global admin pass:
        for (RoleInfo roleInfo : roleInfoList) {
            if (AuthConstants.GLOBAL_ADMIN_ROLE.equals(roleInfo.getRole())) {
                return true;
            }
            if (AuthConstants.GLOBAL_READONLY_ROLE.equals(roleInfo.getRole()) && permissions.stream().allMatch(b -> ActionTypes.READ.toString().equals(b.getAction()))) {
                return true;
            }
        }

        for (Permission permission : permissions) {
            List<AbacRomePermissionInfo> abacRomePermissionInfoList = romePermissionInfoMap.get(username);
            if (Collections.isEmpty(abacRomePermissionInfoList)) {
                continue;
            }
            for (AbacRomePermissionInfo abacRomePermissionInfo : abacRomePermissionInfoList) {
                if (!this.checkRomePermission(permission, abacRomePermissionInfo))
                    return false;
            }
        }
        return true;
    }


    /***
     * 检查用户行为 是否 通过罗马权限校验
     * @param permission
     * @param abacRomePermissionInfo
     * @return
     */
    private boolean checkRomePermission(Permission permission, AbacRomePermissionInfo abacRomePermissionInfo) {
        Resource resource = permission.getResource();
        //如果是模糊匹配,默认给与权限
        if (resource.getName().startsWith("*") && resource.getName().endsWith("*")) return true;

        if (!StringUtils.equals(resource.getName(), abacRomePermissionInfo.getDataId())) return false;
        if (StringUtils.isNotEmpty(abacRomePermissionInfo.getAction()) && abacRomePermissionInfo.getAction().contains(permission.getAction()))
            return true;
        return false;
    }


    /***
     * 根据 role 获取 role 对应的权限 infos.
     * @param permission
     * @param username
     * @return
     */
    public List<AbacRomePermissionInfo> getRomePermissions(Permission permission, String username) {
        String dataid = permission.getResource().getName();
        List<AbacRomePermissionInfo> abacRomePermissionInfoList = romePermissionInfoMap.get(username);
        if (!authConfigs.isCachingEnabled() || abacRomePermissionInfoList == null) {
            List<AbacRomePermissionInfo> abacRomePermissionInfos = getRomePermissionsByDataIdAndUsernameFromDatabase(dataid, username);
            if (abacRomePermissionInfos != null) {
                if (!Collections.isEmpty(abacRomePermissionInfos)) {
                    romePermissionInfoMap.put(username, abacRomePermissionInfos);
                }
            }
        }
        return abacRomePermissionInfoList;
    }

    /***
     *
     * 根据dataId,username获取对应的 Abac权限 infos.
     * @param dataid
     * @param username
     * @return
     */
    public List<AbacRomePermissionInfo> getRomePermissionsByDataIdAndUsernameFromDatabase(String dataid, String username) {
        return abacRomePermissionPersistService.findRomePermissionByDataidAndUsername(dataid, username);
    }

}