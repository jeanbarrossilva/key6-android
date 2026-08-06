/*
 * Copyright © Jean Silva
 *
 * This file is part of the Key6 open-source project.
 *
 * Key6 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * Key6 is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses.
 */

package com.jeanbarrossilva.key6.feature.locket

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.jeanbarrossilva.key6.feature.locket.databinding.FragmentLocketBinding

class LocketFragment : Fragment() {
  private var binding: FragmentLocketBinding? = null

  override fun onCreateView(
    inflater: LayoutInflater,
    container: ViewGroup?,
    savedInstanceState: Bundle?
  ): View? {
    binding = FragmentLocketBinding.inflate(inflater)
    return binding?.root
  }

  override fun onDestroyView() {
    super.onDestroyView()
    binding = null
  }
}
