/*
 * Copyright 1999-2021 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.auth.impl;

import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.roles.RomeNacosRoleServiceImpl;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
  * 来伊份权限插件service implementation.
  * @author: caoxingming
  * @data: 2023/3/30 4:37 PM
  * @description: 来伊份权限插件service implementation.
  **/
@Component
public class RomeNacosAuthManager {

    @Autowired
    private RomeNacosRoleServiceImpl romeNacosRoleService;

    /***
     * 校验来伊份用户账号权限
     * @param permission 用户操作的权限实体
     * @param user 用户信息
     */
    public void auth(Permission permission, NacosUser user) throws AccessException{
        if (Loggers.AUTH.isDebugEnabled()) {
            Loggers.AUTH.debug("auth permission: {}, user: {}", permission, user);
        }
        if (Loggers.AUTH.isDebugEnabled()) {
            Loggers.AUTH.debug("auth permission: {}, user: {}", permission, user);
        }

        if (!romeNacosRoleService.hasPermission(user.getUserName(), permission)) {
            throw new AccessException("authorization failed!");
        }
    }

}
