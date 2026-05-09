/*
 * Crimson Authorizer - Automated Authorization Testing for OWASP ZAP.
 *
 * Renico Koen / crimsonwall.com / 2026.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.crimsonwall.crimsonauthorizer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class ReflectionUtils {

    private static final Logger LOGGER = LogManager.getLogger(ReflectionUtils.class);

    private ReflectionUtils() {}

    public static Object invokeMethod(Object obj, String methodName, Object... args) {
        if (obj == null) {
            return null;
        }
        try {
            Class<?>[] paramTypes = new Class<?>[args.length];
            for (int i = 0; i < args.length; i++) {
                paramTypes[i] = args[i] != null ? args[i].getClass() : Object.class;
            }
            java.lang.reflect.Method method = obj.getClass().getMethod(methodName, paramTypes);
            return method.invoke(obj, args);
        } catch (Exception e) {
            LOGGER.debug("Reflection error calling {}.{}",
                    obj.getClass().getSimpleName(), methodName, e);
            return null;
        }
    }
}
