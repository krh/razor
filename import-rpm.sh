#!/bin/sh

import_rpm() {
    echo "<package name=\"$p\" version=\"3.2\" build=\"9\">"
    echo "  <properties>"

    rpm -q --provides $p | sort -u | while read name ignore version; do
	echo "    <provides name=\"$name\"/>"
    done

    rpm -q --requires $p | sort -u | while read name ignore version; do
	echo "    <requires name=\"$name\"/>"
    done

    echo "  </properties>"
    echo "</package>"
}

mkdir pkgs
rpm -qa | while read p; do
    base=${p%-*-*}
    echo $base
    import_rpm $base > pkgs/$base.rzr
done
