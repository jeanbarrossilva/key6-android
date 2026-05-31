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

import org.jetbrains.annotations.NotNull;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * An exception thrown to signal that a retry operation (executed via {@link RetryRule}) has retried more than the
 * allowed number of times, and has still failed.
 */
public final class RetryException extends RuntimeException {

  /**
   * @param errors the errors for each attempt at running this test-case
   */
  @NotNull public static RetryException from(@NotNull Throwable[] errors) {
    final StringBuilder msg = new StringBuilder("Invoked methods still failed after " + errors.length + " attempts.");
    for (int i = 0; i < errors.length; i++) {
      final Throwable error = errors[i];
      msg.append('\n');
      msg.append("Attempt #").append(i).append(" threw exception:");
      msg.append(stackTraceAsString(error));
    }
    return new RetryException(msg.toString());
  }

  private RetryException(@NotNull String message) {
    super(message);
  }


  @NotNull private static String stackTraceAsString(@NotNull Throwable t) {
    final StringWriter errors = new StringWriter();
    t.printStackTrace(new PrintWriter(errors));
    return errors.toString();
  }
}
