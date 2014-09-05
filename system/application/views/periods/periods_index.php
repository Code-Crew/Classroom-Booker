<?php echo $this->session->flashdata('saved') ?>
<?php
$icondata[0] = array('periods/add', 'Add Period', 'add.gif' );
$this->load->view('partials/iconbar', $icondata);
?>
<table width="100%" cellpadding="2" cellspacing="2" border="0" class="sort-table" id="jsst-periods">
	<col /><col /><col /><col />
	<thead>
	<tr class="heading">
		<td class="h" title="N">&nbsp;</td>
		<td class="h" title="Name">Name</td>
		<td class="h" title="TimeStart">Start time</td>
		<td class="h" title="TimeEnd">End Time</td>
		<td class="h" title="Duration">Duration</td>
		<td class="h" title="Days">Days of week</td>
		<td class="n" title="X"></td>
	</tr>
	</thead>
	<tbody>
	<?php
	$i=0;
	if( $periods ){
	foreach( $periods as $period ){
		// Get UNIX timestamp of times to do calculations on
		$time_start = strtotime($period->time_start);
		$time_end = strtotime($period->time_end);
		$days_bitmask->reverse_mask($period->days);
	?>
	<tr class="tr<?php echo ($i & 1) ?>">
		<?php
		// $now = timestamp to do calculations with for "current" period
		$now = now();
		// $dayofweek = numeric day of week (1=monday) to get "current" period for periods on this day of the week
		$dayofweek = date('N', $now);

		if( ($now >= $time_start) && ($now < $time_end) && ($days_bitmask->bit_isset($dayofweek) ) ){
			$now_img = '<img src="webroot/images/ui/school_manage_times.gif" width="16" height="16" alt="Now" />';
		} else {
			$now_img = '';
		}
		?>
		<td width="20" align="center"><?php echo $now_img ?></td>
		<td><?php echo $period->name ?></td>
		<td><?php echo strftime('%H:%M', $time_start) ?></td>
		<td><?php echo strftime('%H:%M', $time_end) ?></td>
		<td><?php echo timespan($time_start, $time_end) ?></td>
		<td><?php
		foreach($days_list as $day_num => $day_name){
			$days_bitmask->reverse_mask($period->days);
			$day = $days_bitmask->bit_isset($day_num) ? '%s' : '<span style="color:#ccc">%s</span>';
			$day_letter = $day_name{0};
			echo sprintf($day, $day_letter) . ' ';
		}
		?></td>
		<td width="45" class="n"><?php
			$actions['edit'] = 'periods/edit/'.$period->period_id;
			$actions['delete'] = 'periods/delete/'.$period->period_id;
			$this->load->view('partials/editdelete', $actions);
			?>
		</td>
	</tr>
	<?php $i++; }
	} else {
		echo '<td colspan="7" align="center" style="padding:16px 0">No periods exist!</td>';
	}
	?>
	</tbody>
</table>
<?php $this->load->view('partials/iconbar', $icondata) ?>
<?php
$jsst['name'] = 'st1';
$jsst['id'] = 'jsst-periods';
$jsst['cols'] = array("None", "Name", "TimeStart", "TimeEnd", "Duration", "Days", "None");
$this->load->view('partials/js-sorttable', $jsst);
?>
