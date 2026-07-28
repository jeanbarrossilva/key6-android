/*
 * Copyright © 2016 Kevin Most
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.kevinmost.junit_retry_rule;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Retries a unit-test according to the attributes set here
 *
 * <p>The class containing the test(s) decorated with this annotation must have a public field of
 * type {@link RetryRule}
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface Retry {
  /**
   * @return the number of times to try this method before the failure is propagated through
   */
  int times() default 3;

  /**
   * @return how long to sleep between invocations of the unit tests, in milliseconds
   */
  long timeout() default 0;
}
