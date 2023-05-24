package com.alibaba.nacos.plugin.auth.impl.aspect;

import com.alibaba.nacos.auth.config.AuthConfigs;
import com.alibaba.nacos.common.utils.*;
import com.alibaba.nacos.common.model.RestResult;
import com.alibaba.nacos.common.model.RestResultUtils;
import com.alibaba.nacos.common.utils.DateFormatUtils;
import com.alibaba.nacos.common.utils.NamespaceUtil;
import com.alibaba.nacos.common.utils.Pair;
import com.alibaba.nacos.config.server.controller.ConfigController;
import com.alibaba.nacos.config.server.model.ConfigAllInfo;
import com.alibaba.nacos.config.server.model.ConfigInfo;
import com.alibaba.nacos.config.server.model.ConfigMetadata;
import com.alibaba.nacos.config.server.model.SameConfigPolicy;
import com.alibaba.nacos.config.server.model.event.ConfigDataChangeEvent;
import com.alibaba.nacos.config.server.result.code.ResultCodeEnum;
import com.alibaba.nacos.config.server.service.ConfigChangePublisher;
import com.alibaba.nacos.config.server.service.repository.CommonPersistService;
import com.alibaba.nacos.config.server.service.repository.ConfigInfoPersistService;
import com.alibaba.nacos.config.server.service.trace.ConfigTraceService;
import com.alibaba.nacos.config.server.utils.*;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.api.Resource;
import com.alibaba.nacos.plugin.auth.constant.ActionTypes;
import com.alibaba.nacos.plugin.auth.constant.Constants;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.persistence.RoleInfo;
import com.alibaba.nacos.plugin.auth.impl.persistence.RomeConfigInfoPersistService;
import com.alibaba.nacos.plugin.auth.impl.result.code.RomeResultCodeEnum;
import com.alibaba.nacos.plugin.auth.impl.roles.NacosRoleServiceImpl;
import com.alibaba.nacos.plugin.auth.impl.roles.RomeNacosRoleServiceImpl;
import com.alibaba.nacos.plugin.encryption.handler.EncryptionHandler;
import com.alibaba.nacos.sys.utils.InetUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 来伊份个性化权限控制请求切面
 * @author caoxingming
 * @name RomeRequestAspect
 * @date 2023-04-06-10:55 AM
 * @description: 来伊份个性化权限控制请求切面
 */
@Aspect
@Component
public class RomeRequestAspect {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigController.class);


    @Autowired
    private NacosRoleServiceImpl nacosRoleService;

    @Autowired
    private RomeConfigInfoPersistService romeConfigInfoPersistService;

    private static final String EXPORT_CONFIG_FILE_NAME = "nacos_config_export_";


    private static final String EXPORT_CONFIG_FILE_NAME_EXT = ".zip";

    private static final String EXPORT_CONFIG_FILE_NAME_DATE_FORMAT = "yyyyMMddHHmmss";


    private CommonPersistService commonPersistService;

    private ConfigInfoPersistService configInfoPersistService;


    @Autowired
    private RomeNacosRoleServiceImpl romeNacosRoleService;

    @Autowired
    private AuthConfigs authConfigs;

    /**
     * Config Get config.
     */
    private static final String CLIENT_INTERFACE_GET_CONFIG =
            "execution(* com.alibaba.nacos.config.server.controller.ConfigController.searchConfig(..)) && args(dataId," +
                    "group,appName,tenant,configTags,pageNo,pageSize,..)";

    /**
     * Config Get config.
     */
    private static final String CLIENT_INTERFACE_EXPORT_CONFIG =
            "execution(* com.alibaba.nacos.config.server.controller.ConfigController.exportConfig(..)) && args(dataId," +
                    "group,appName,tenant,ids,..)";

    /**
     * Config Get config.
     */
    private static final String CLIENT_INTERFACE_EXPORT_CONFIG_V2 =
            "execution(* com.alibaba.nacos.config.server.controller.ConfigController.exportConfigV2(..)) && args(dataId," +
                    "group,appName,tenant,ids,..)";


    /**
     * Config Get config.
     */
    private static final String CLIENT_INTERFACE_IMPORT_CONFIG =
            "execution(* com.alibaba.nacos.config.server.controller.ConfigController.importAndPublishConfig(..)) && args(request," +
                    "srcUser,namespace,policy,file,..)";



    public RomeRequestAspect(CommonPersistService commonPersistService,ConfigInfoPersistService configInfoPersistService) {
        this.commonPersistService = commonPersistService;
        this.configInfoPersistService = configInfoPersistService;
    }

    /**
     * Config Get config.
     */
    @Around(CLIENT_INTERFACE_GET_CONFIG)
    public Object interfaceSearchConfig(ProceedingJoinPoint pjp, String dataId, String group,String appName,String tenant, String configTags,int pageNo,int pageSize) throws Throwable {
        if(!AuthConstants.ROME_AUTH_PLUGIN_TYPE.equals(authConfigs.getNacosAuthSystemType())) {
            return pjp.proceed();
        }

        Map<String, Object> configAdvanceInfo = new HashMap<>(100);
        if (StringUtils.isNotBlank(appName)) {
            configAdvanceInfo.put("appName", appName);
        }
        if (StringUtils.isNotBlank(configTags)) {
            configAdvanceInfo.put("config_tags", configTags);
        }

        List<String> roles = getUsernameAndRolesFromAttributes();

        try {
            return romeConfigInfoPersistService.findConfigInfo4Page(pageNo, pageSize, dataId, group, tenant, configAdvanceInfo, roles);
        } catch (Exception e) {
            String errorMsg = "serialize page error, dataId=" + dataId + ", group=" + group;
            throw new RuntimeException(errorMsg, e);
        }
    }

    /**
     * Config export.
     */
    @Around(CLIENT_INTERFACE_EXPORT_CONFIG)
    public Object interfaceExportConfig(ProceedingJoinPoint pjp, String dataId, String group,String appName,String tenant, List<Long> ids) throws Throwable {
        if(!AuthConstants.ROME_AUTH_PLUGIN_TYPE.equals(authConfigs.getNacosAuthSystemType())) {
            return pjp.proceed();
        }
        ids.removeAll(Collections.singleton(null));
        tenant = NamespaceUtil.processNamespaceParameter(tenant);
        List<String> roles = getUsernameAndRolesFromAttributes();

        List<ConfigAllInfo> dataList = romeConfigInfoPersistService.findAllConfigInfo4Export(dataId, group, tenant, appName, ids, roles);
        List<ZipUtils.ZipItem> zipItemList = new ArrayList<>();
        StringBuilder metaData = null;
        for (ConfigInfo ci : dataList) {
            if (StringUtils.isNotBlank(ci.getAppName())) {
                // Handle appName
                if (metaData == null) {
                    metaData = new StringBuilder();
                }
                String metaDataId = ci.getDataId();
                if (metaDataId.contains(".")) {
                    metaDataId = metaDataId.substring(0, metaDataId.lastIndexOf(".")) + "~" + metaDataId
                            .substring(metaDataId.lastIndexOf(".") + 1);
                }
                metaData.append(ci.getGroup()).append('.').append(metaDataId).append(".app=")
                        // Fixed use of "\r\n" here
                        .append(ci.getAppName()).append("\r\n");
            }
            Pair<String, String> pair = EncryptionHandler
                    .decryptHandler(ci.getDataId(), ci.getEncryptedDataKey(), ci.getContent());
            String itemName = ci.getGroup() + com.alibaba.nacos.config.server.constant.Constants.CONFIG_EXPORT_ITEM_FILE_SEPARATOR + ci.getDataId();
            zipItemList.add(new ZipUtils.ZipItem(itemName, pair.getSecond()));
        }
        if (metaData != null) {
            zipItemList.add(new ZipUtils.ZipItem(com.alibaba.nacos.config.server.constant.Constants.CONFIG_EXPORT_METADATA, metaData.toString()));
        }

        HttpHeaders headers = new HttpHeaders();
        String fileName =
                EXPORT_CONFIG_FILE_NAME + DateFormatUtils.format(new Date(), EXPORT_CONFIG_FILE_NAME_DATE_FORMAT)
                        + EXPORT_CONFIG_FILE_NAME_EXT;
        headers.add("Content-Disposition", "attachment;filename=" + fileName);
        return new ResponseEntity<>(ZipUtils.zip(zipItemList), headers, HttpStatus.OK);
    }

    /**
     * Config exportV2.
     */
    @Around(CLIENT_INTERFACE_EXPORT_CONFIG_V2)
    public Object interfaceExportConfigV2(ProceedingJoinPoint pjp, String dataId, String group,String appName,String tenant, List<Long> ids) throws Throwable {
        if(!AuthConstants.ROME_AUTH_PLUGIN_TYPE.equals(authConfigs.getNacosAuthSystemType())) {
            return pjp.proceed();
        }
        ids.removeAll(Collections.singleton(null));
        tenant = NamespaceUtil.processNamespaceParameter(tenant);
        List<String> roles = getUsernameAndRolesFromAttributes();

        List<ConfigAllInfo> dataList = romeConfigInfoPersistService.findAllConfigInfo4Export(dataId, group, tenant, appName, ids, roles);
        List<ZipUtils.ZipItem> zipItemList = new ArrayList<>();
        StringBuilder metaData = null;
        for (ConfigInfo ci : dataList) {
            if (StringUtils.isNotBlank(ci.getAppName())) {
                // Handle appName
                if (metaData == null) {
                    metaData = new StringBuilder();
                }
                String metaDataId = ci.getDataId();
                if (metaDataId.contains(".")) {
                    metaDataId = metaDataId.substring(0, metaDataId.lastIndexOf(".")) + "~" + metaDataId
                            .substring(metaDataId.lastIndexOf(".") + 1);
                }
                metaData.append(ci.getGroup()).append('.').append(metaDataId).append(".app=")
                        // Fixed use of "\r\n" here
                        .append(ci.getAppName()).append("\r\n");
            }
            Pair<String, String> pair = EncryptionHandler
                    .decryptHandler(ci.getDataId(), ci.getEncryptedDataKey(), ci.getContent());
            String itemName = ci.getGroup() + com.alibaba.nacos.config.server.constant.Constants.CONFIG_EXPORT_ITEM_FILE_SEPARATOR + ci.getDataId();
            zipItemList.add(new ZipUtils.ZipItem(itemName, pair.getSecond()));
        }
        if (metaData != null) {
            zipItemList.add(new ZipUtils.ZipItem(com.alibaba.nacos.config.server.constant.Constants.CONFIG_EXPORT_METADATA, metaData.toString()));
        }

        HttpHeaders headers = new HttpHeaders();
        String fileName =
                EXPORT_CONFIG_FILE_NAME + DateFormatUtils.format(new Date(), EXPORT_CONFIG_FILE_NAME_DATE_FORMAT)
                        + EXPORT_CONFIG_FILE_NAME_EXT;
        headers.add("Content-Disposition", "attachment;filename=" + fileName);
        return new ResponseEntity<>(ZipUtils.zip(zipItemList), headers, HttpStatus.OK);
    }


    @Around(CLIENT_INTERFACE_IMPORT_CONFIG)
    public Object interfaceExportConfigV2(ProceedingJoinPoint pjp, HttpServletRequest request,String srcUser,String namespace,SameConfigPolicy policy, MultipartFile file) throws Throwable {
        if(!AuthConstants.ROME_AUTH_PLUGIN_TYPE.equals(authConfigs.getNacosAuthSystemType())) {
            return pjp.proceed();
        }

        Map<String, Object> failedData = new HashMap<>(4);

        if (Objects.isNull(file)) {
            return RestResultUtils.buildResult(ResultCodeEnum.DATA_EMPTY, failedData);
        }

        namespace = NamespaceUtil.processNamespaceParameter(namespace);
        if (StringUtils.isNotBlank(namespace) && commonPersistService.tenantInfoCountByTenantId(namespace) <= 0) {
            failedData.put("succCount", 0);
            return RestResultUtils.buildResult(ResultCodeEnum.NAMESPACE_NOT_EXIST, failedData);
        }
        List<ConfigAllInfo> configInfoList = new ArrayList<>();
        List<Map<String, String>> unrecognizedList = new ArrayList<>();
        try {
            ZipUtils.UnZipResult unziped = ZipUtils.unzip(file.getBytes());
            ZipUtils.ZipItem metaDataZipItem = unziped.getMetaDataItem();
            RestResult<Map<String, Object>> errorResult;
            if (metaDataZipItem != null && com.alibaba.nacos.config.server.constant.Constants.CONFIG_EXPORT_METADATA_NEW.equals(metaDataZipItem.getItemName())) {
                // new export
                errorResult = parseImportDataV2(unziped, configInfoList, unrecognizedList, namespace);
            } else {
                errorResult = parseImportData(unziped, configInfoList, unrecognizedList, namespace);
            }
            if (errorResult != null) {
                return errorResult;
            }
        } catch (IOException e) {
            failedData.put("succCount", 0);
            LOGGER.error("parsing data failed", e);
            return RestResultUtils.buildResult(ResultCodeEnum.PARSING_DATA_FAILED, failedData);
        }

        String username = getUsernameFromAttributes();
        Boolean permissionResult = this.checkConfigInfoListExistRoleWithPermission(configInfoList,username);
        if(!permissionResult) {
            return RestResultUtils.failedWithMsg(RomeResultCodeEnum.INSUFFICIENT_PERMISSION_CONFIG.getCode(),RomeResultCodeEnum.INSUFFICIENT_PERMISSION_CONFIG.getCodeMsg());
        }

        if (org.springframework.util.CollectionUtils.isEmpty(configInfoList)) {
            failedData.put("succCount", 0);
            return RestResultUtils.buildResult(ResultCodeEnum.DATA_EMPTY, failedData);
        }
        final String srcIp = RequestUtil.getRemoteIp(request);
        String requestIpApp = RequestUtil.getAppName(request);
        final Timestamp time = TimeUtils.getCurrentTime();

        Map<String, Object> saveResult = configInfoPersistService
                .batchInsertOrUpdate(configInfoList, srcUser, srcIp, null, time, false, policy);
        for (ConfigInfo configInfo : configInfoList) {
            ConfigChangePublisher.notifyConfigChange(
                    new ConfigDataChangeEvent(false, configInfo.getDataId(), configInfo.getGroup(),
                            configInfo.getTenant(), time.getTime()));
            ConfigTraceService
                    .logPersistenceEvent(configInfo.getDataId(), configInfo.getGroup(), configInfo.getTenant(),
                            requestIpApp, time.getTime(), InetUtils.getSelfIP(),
                            ConfigTraceService.PERSISTENCE_EVENT_PUB, configInfo.getContent());
        }
        // unrecognizedCount
        if (!unrecognizedList.isEmpty()) {
            saveResult.put("unrecognizedCount", unrecognizedList.size());
            saveResult.put("unrecognizedData", unrecognizedList);
        }
        return RestResultUtils.success("导入成功", saveResult);
    }


    /**
     * 查询鉴权后的 username 及对应的 角色列表
     * @return  username 对应 role list
     */
    private List<String> getUsernameAndRolesFromAttributes() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        String username = (String)request.getAttribute(Constants.Identity.IDENTITY_ID);
        List<String> roles = nacosRoleService.getRoles(username).stream().map(RoleInfo::getRole).collect(Collectors.toList());
        return roles;
    }


    /**
     * 查询鉴权后的 username
     * @return  username
     */
    private String getUsernameFromAttributes() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        return (String)request.getAttribute(Constants.Identity.IDENTITY_ID);
    }


    /**
     * old import config.
     *
     * @param unziped          export file.
     * @param configInfoList   parse file result.
     * @param unrecognizedList unrecognized file.
     * @param namespace        import namespace.
     * @return error result.
     */
    private RestResult<Map<String, Object>> parseImportData(ZipUtils.UnZipResult unziped,
                                                            List<ConfigAllInfo> configInfoList, List<Map<String, String>> unrecognizedList, String namespace) {
        ZipUtils.ZipItem metaDataZipItem = unziped.getMetaDataItem();

        Map<String, String> metaDataMap = new HashMap<>(16);
        if (metaDataZipItem != null) {
            // compatible all file separator
            String metaDataStr = metaDataZipItem.getItemData().replaceAll("[\r\n]+", "|");
            String[] metaDataArr = metaDataStr.split("\\|");
            Map<String, Object> failedData = new HashMap<>(4);
            for (String metaDataItem : metaDataArr) {
                String[] metaDataItemArr = metaDataItem.split("=");
                if (metaDataItemArr.length != 2) {
                    failedData.put("succCount", 0);
                    return RestResultUtils.buildResult(ResultCodeEnum.METADATA_ILLEGAL, failedData);
                }
                metaDataMap.put(metaDataItemArr[0], metaDataItemArr[1]);
            }
        }

        List<ZipUtils.ZipItem> itemList = unziped.getZipItemList();
        if (itemList != null && !itemList.isEmpty()) {
            for (ZipUtils.ZipItem item : itemList) {
                String[] groupAdnDataId = item.getItemName().split(com.alibaba.nacos.config.server.constant.Constants.CONFIG_EXPORT_ITEM_FILE_SEPARATOR);
                if (groupAdnDataId.length != 2) {
                    Map<String, String> unrecognizedItem = new HashMap<>(2);
                    unrecognizedItem.put("itemName", item.getItemName());
                    unrecognizedList.add(unrecognizedItem);
                    continue;
                }
                String group = groupAdnDataId[0];
                String dataId = groupAdnDataId[1];
                String tempDataId = dataId;
                if (tempDataId.contains(".")) {
                    tempDataId = tempDataId.substring(0, tempDataId.lastIndexOf(".")) + "~" + tempDataId
                            .substring(tempDataId.lastIndexOf(".") + 1);
                }
                final String metaDataId = group + "." + tempDataId + ".app";

                //encrypted
                String content = item.getItemData();
                Pair<String, String> pair = EncryptionHandler.encryptHandler(dataId, content);
                content = pair.getSecond();

                ConfigAllInfo ci = new ConfigAllInfo();
                ci.setGroup(group);
                ci.setDataId(dataId);
                ci.setContent(content);
                if (metaDataMap.get(metaDataId) != null) {
                    ci.setAppName(metaDataMap.get(metaDataId));
                }
                ci.setTenant(namespace);
                ci.setEncryptedDataKey(pair.getFirst());
                configInfoList.add(ci);
            }
        }
        return null;
    }

    /**
     * new version import config add .metadata.yml file.
     *
     * @param unziped          export file.
     * @param configInfoList   parse file result.
     * @param unrecognizedList unrecognized file.
     * @param namespace        import namespace.
     * @return error result.
     */
    private RestResult<Map<String, Object>> parseImportDataV2(ZipUtils.UnZipResult unziped,
                                                              List<ConfigAllInfo> configInfoList, List<Map<String, String>> unrecognizedList, String namespace) {
        ZipUtils.ZipItem metaDataItem = unziped.getMetaDataItem();
        String metaData = metaDataItem.getItemData();
        Map<String, Object> failedData = new HashMap<>(4);

        ConfigMetadata configMetadata = YamlParserUtil.loadObject(metaData, ConfigMetadata.class);
        if (configMetadata == null || org.springframework.util.CollectionUtils.isEmpty(configMetadata.getMetadata())) {
            failedData.put("succCount", 0);
            return RestResultUtils.buildResult(ResultCodeEnum.METADATA_ILLEGAL, failedData);
        }
        List<ConfigMetadata.ConfigExportItem> configExportItems = configMetadata.getMetadata();
        // check config metadata
        for (ConfigMetadata.ConfigExportItem configExportItem : configExportItems) {
            if (StringUtils.isBlank(configExportItem.getDataId()) || StringUtils.isBlank(configExportItem.getGroup())
                    || StringUtils.isBlank(configExportItem.getType())) {
                failedData.put("succCount", 0);
                return RestResultUtils.buildResult(ResultCodeEnum.METADATA_ILLEGAL, failedData);
            }
        }

        List<ZipUtils.ZipItem> zipItemList = unziped.getZipItemList();
        Set<String> metaDataKeys = configExportItems.stream()
                .map(metaItem -> GroupKey.getKey(metaItem.getDataId(), metaItem.getGroup()))
                .collect(Collectors.toSet());

        Map<String, String> configContentMap = new HashMap<>(zipItemList.size());
        int itemNameLength = 2;
        zipItemList.forEach(item -> {
            String itemName = item.getItemName();
            String[] groupAdnDataId = itemName.split(com.alibaba.nacos.config.server.constant.Constants.CONFIG_EXPORT_ITEM_FILE_SEPARATOR);
            if (groupAdnDataId.length != itemNameLength) {
                Map<String, String> unrecognizedItem = new HashMap<>(2);
                unrecognizedItem.put("itemName", item.getItemName());
                unrecognizedList.add(unrecognizedItem);
                return;
            }

            String group = groupAdnDataId[0];
            String dataId = groupAdnDataId[1];
            String key = GroupKey.getKey(dataId, group);
            // metadata does not contain config file
            if (!metaDataKeys.contains(key)) {
                Map<String, String> unrecognizedItem = new HashMap<>(2);
                unrecognizedItem.put("itemName", "未在元数据中找到: " + item.getItemName());
                unrecognizedList.add(unrecognizedItem);
                return;
            }
            String itemData = item.getItemData();
            configContentMap.put(key, itemData);
        });

        for (ConfigMetadata.ConfigExportItem configExportItem : configExportItems) {
            String dataId = configExportItem.getDataId();
            String group = configExportItem.getGroup();
            String content = configContentMap.get(GroupKey.getKey(dataId, group));
            // config file not in metadata
            if (content == null) {
                Map<String, String> unrecognizedItem = new HashMap<>(2);
                unrecognizedItem.put("itemName", "未在文件中找到: " + group + "/" + dataId);
                unrecognizedList.add(unrecognizedItem);
                continue;
            }
            // encrypted
            Pair<String, String> pair = EncryptionHandler.encryptHandler(dataId, content);
            content = pair.getSecond();

            ConfigAllInfo ci = new ConfigAllInfo();
            ci.setGroup(group);
            ci.setDataId(dataId);
            ci.setContent(content);
            ci.setType(configExportItem.getType());
            ci.setDesc(configExportItem.getDesc());
            ci.setAppName(configExportItem.getAppName());
            ci.setTenant(namespace);
            ci.setEncryptedDataKey(pair.getFirst());
            configInfoList.add(ci);
        }
        return null;
    }

    /**
     * check all configInfo with user's roles
     *
     * @param configInfoList
     * @param username
     * @return
     */
    public Boolean checkConfigInfoListExistRoleWithPermission(List<ConfigAllInfo> configInfoList, String username) {
        //构建permissions
        List<Permission> permissions = new ArrayList<>();
        configInfoList.stream().forEach(configInfo -> {
            Permission permission = new Permission();
            Resource resource = new Resource(null,configInfo.getGroup(),configInfo.getDataId(), null,null);
            permission.setResource(resource);
            permission.setAction(ActionTypes.WRITE.toString());
            permissions.add(permission);
        });

        return romeNacosRoleService.romeUserHasAllPermission(username, permissions);
    }
}
