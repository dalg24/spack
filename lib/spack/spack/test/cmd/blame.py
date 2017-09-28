##############################################################################
# Copyright (c) 2013-2017, Lawrence Livermore National Security, LLC.
# Produced at the Lawrence Livermore National Laboratory.
#
# This file is part of Spack.
# Created by Todd Gamblin, tgamblin@llnl.gov, All rights reserved.
# LLNL-CODE-647188
#
# For details, see https://github.com/llnl/spack
# Please also see the NOTICE and LICENSE files for our notice and the LGPL.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License (as
# published by the Free Software Foundation) version 2.1, February 1999.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the IMPLIED WARRANTY OF
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the terms and
# conditions of the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
##############################################################################
import pytest

import spack.cmd
from spack.main import SpackCommand
from spack.util.executable import which

pytestmark = pytest.mark.skipif(
    not which('git') or not spack.cmd.spack_is_git_repo(),
    reason="needs git")

blame = SpackCommand('blame')


def test_blame_by_modtime(builtin_mock):
    """Sanity check the blame command to make sure it works."""
    out = blame('--time', 'mpich')
    assert 'LAST_COMMIT' in out
    assert 'AUTHOR' in out
    assert 'EMAIL' in out


def test_blame_by_percent(builtin_mock):
    """Sanity check the blame command to make sure it works."""
    out = blame('--percent', 'mpich')
    assert 'LAST_COMMIT' in out
    assert 'AUTHOR' in out
    assert 'EMAIL' in out


def test_blame_by_git(builtin_mock, capsys):
    """Sanity check the blame command to make sure it works."""
    with capsys.disabled():
        out = blame('--git', 'mpich')
    assert 'Mpich' in out
    assert 'mock_packages' in out
