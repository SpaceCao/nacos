package com.alibaba.nacos.plugin.auth.impl.persistence;

import com.alibaba.nacos.config.server.model.ConfigAllInfo;
import com.alibaba.nacos.config.server.model.ConfigInfo;
import com.alibaba.nacos.config.server.model.Page;

import java.util.List;
import java.util.Map;

/**
  * 来伊份个性化配置中心持久层 Interface.
  * @author: caoxingming
  * @date: 2023/4/6 3:26 PM
  * @description: 来伊份个性化配置中心持久层 Interface.用于权限控制
  **/
public interface RomeConfigInfoPersistService {


    /**
     * find config info.
     * @param pageNo            page number
     * @param pageSize          page size
     * @param dataId            data id
     * @param group             group
     * @param tenant            tenant
     * @param configAdvanceInfo advance info
     * @param roles             roles
     * @return {@link Page} with {@link ConfigInfo} generation
     */
    Page<ConfigInfo> findConfigInfo4Page(final int pageNo, final int pageSize, final String dataId, final String group,
                                         final String tenant, final Map<String, Object> configAdvanceInfo, List<String> roles);

    /**
     * query all configuration information according to group, appName, tenant (for export).
     * @param dataId
     * @param group
     * @param tenant
     * @param appName
     * @param ids
     * @param roles
     * @return
     */
    List<ConfigAllInfo> findAllConfigInfo4Export(String dataId, String group, String tenant, String appName, List<Long> ids, List<String> roles);

}
