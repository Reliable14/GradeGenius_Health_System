<?php
/**
 * Sample custom technician probe for DevSentinel.
 * Exit 0 for OK, 1 for WARN, 2 for FAIL.
 * Any printed output will appear in the dashboard details.
 */
echo "Technician custom probe active: all microservices reachable.";
exit(0);
